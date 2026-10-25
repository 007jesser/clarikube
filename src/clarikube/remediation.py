"""Turn remediation hints into concrete manifest edits in a GitOps repo.

Automatable kinds edit or add files. Everything else is returned as manual guidance — clarikube
never creates secrets, rotates credentials or edits RBAC on its own.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import LiteralScalarString

from clarikube import quantity
from clarikube.engine import fluentbit
from clarikube.gitops import helm
from clarikube.gitops import manifests as mf
from clarikube.models import RemediationHint, WorkloadRef
from clarikube.policy import PolicyResult, compare
from clarikube.source.base import Snapshot

FIELD_KINDS = {
    "set-memory-limit",
    "set-memory-request",
    "set-image",
    "rollback-template",
    "harden-security-context",
    "set-kafka-config",
    "set-modsecurity-blocking",
    "set-fluentbit-option",
    "add-toleration",
}
NEW_FILE_KINDS = {"restrict-ingress", "isolate-workload", "add-pdb"}
SERVICE_KINDS = {"make-service-internal"}
AUTOMATABLE = FIELD_KINDS | NEW_FILE_KINDS | SERVICE_KINDS
HELM_KINDS = {"set-memory-limit", "set-memory-request", "set-image"}
# Operator CRs whose resources live outside a pod template: kind -> path of the map holding "resources".
_CR_RESOURCES: dict[str, tuple[str, ...]] = {
    "Kafka": ("spec", "kafka"),
    "KafkaNodePool": ("spec",),
    "RabbitmqCluster": ("spec",),
    "Cluster": ("spec",),  # CloudNativePG
    "postgresql": ("spec",),  # Zalando
}
_VOLATILE_LABELS = {
    "pod-template-hash",
    "controller-revision-hash",
    "job-name",
    "controller-uid",
    "batch.kubernetes.io/job-name",
    "batch.kubernetes.io/controller-uid",
    "statefulset.kubernetes.io/pod-name",
}


class RemediationError(Exception):
    pass


@dataclass
class FileChange:
    path: str  # relative to repo root
    before: str | None  # None => new file
    after: str
    policy: list[PolicyResult] = field(default_factory=list)
    deleted: bool = False

    def diff(self) -> str:
        a = (self.before or "").splitlines(keepends=True)
        b = [] if self.deleted else self.after.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                a,
                b,
                fromfile="/dev/null" if self.before is None else f"a/{self.path}",
                tofile="/dev/null" if self.deleted else f"b/{self.path}",
            )
        )


@dataclass
class RemediationResult:
    changes: list[FileChange]
    applied: list[str]  # summaries of edits applied
    manual: list[str]  # guidance the human must act on
    notes: list[str]  # caveats the reviewer must check


# ---------------------------------------------------------------- edit helpers


def _resources_owner(doc: CommentedMap, cname: str) -> CommentedMap:
    """The map that holds ``resources`` for a container: the container itself, or a section of an operator CR."""
    path = _CR_RESOURCES.get(str(doc.get("kind")))
    if path is None:
        return mf.container(doc, cname)
    node: CommentedMap = doc
    for key in path:
        node = mf.ensure_map(node, key)
    return node


def _set_limit(doc: CommentedMap, cname: str, section: str, res: str, value: str) -> str:
    c = _resources_owner(doc, cname)
    resources = mf.ensure_map(c, "resources")
    target = mf.ensure_map(resources, section)
    old = target.get(res)
    target[res] = value
    return f"{cname}: {section}.{res} {old or 'unset'} → {value}"


def _harden(doc: CommentedMap) -> tuple[list[str], list[str]]:
    ps = mf.pod_spec(doc)
    applied, notes = [], []
    pod_sc = mf.ensure_map(ps, "securityContext", before="containers")
    if pod_sc.get("runAsNonRoot") is not True and pod_sc.get("runAsUser") in (None, 0):
        pod_sc["runAsNonRoot"] = True
        applied.append("pod: securityContext.runAsNonRoot → true")
        notes.append(
            "runAsNonRoot: true makes the kubelet refuse images whose USER is root. Verify the image "
            "defines a non-root numeric USER, or add runAsUser to the pod securityContext."
        )
    if "seccompProfile" not in pod_sc:
        pod_sc["seccompProfile"] = CommentedMap(type="RuntimeDefault")
        applied.append("pod: seccompProfile → RuntimeDefault")
    for c in ps.get("containers") or []:
        sc = mf.ensure_map(c, "securityContext")
        if sc.get("privileged"):
            sc["privileged"] = False
            applied.append(f"{c.get('name')}: privileged → false")
        if sc.get("allowPrivilegeEscalation") is not False:
            sc["allowPrivilegeEscalation"] = False
            applied.append(f"{c.get('name')}: allowPrivilegeEscalation → false")
        caps = mf.ensure_map(sc, "capabilities")
        drop = [str(x) for x in caps.get("drop") or []]
        if "ALL" not in drop:
            caps["drop"] = CommentedSeq(["ALL"])
            applied.append(f"{c.get('name')}: capabilities.drop → [ALL]")
        if caps.get("add"):
            notes.append(f"{c.get('name')} still adds capabilities {list(caps['add'])}; review whether needed.")
    notes.append("readOnlyRootFilesystem was NOT enabled automatically (often needs an emptyDir for /tmp).")
    return applied, notes


def _selector_labels(doc: CommentedMap, snap: Snapshot, wl: WorkloadRef) -> dict[str, str]:
    spec = doc.get("spec") or {}
    ml = ((spec.get("selector") or {}).get("matchLabels")) if isinstance(spec, dict) else None
    if ml:
        return {str(k): str(v) for k, v in ml.items()}
    pods = snap.pods_of(wl)
    if pods:
        return {k: v for k, v in pods[0].labels.items() if k not in _VOLATILE_LABELS}
    raise RemediationError("cannot determine pod labels for NetworkPolicy selector")


def _managed_meta(name: str, namespace: str, reason: str) -> dict[str, Any]:
    return {
        "name": name,
        "namespace": namespace,
        "labels": {"app.kubernetes.io/managed-by": "clarikube"},
        "annotations": {"clarikube.io/reason": reason},
    }


def _pdb(name: str, namespace: str, labels: dict[str, str], max_unavailable: int) -> dict[str, Any]:
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": _managed_meta(name, namespace, "Voluntary disruptions (drains, upgrades) one member at a time"),
        "spec": {"maxUnavailable": max_unavailable, "selector": {"matchLabels": labels}},
    }


def _parse_selector(text: str) -> dict[str, str]:
    out = {}
    for part in text.split(","):
        k, sep, v = part.strip().partition("=")
        if not sep or not k:
            raise RemediationError(f"invalid selector {text!r}")
        out[k] = v
    return out


def _netpol(
    wl: WorkloadRef,
    labels: dict[str, str],
    mode: str,
    from_namespaces: list[str] | None = None,
    name: str | None = None,
) -> dict[str, Any]:
    name = (name or f"clarikube-{wl.name}-{'isolate' if mode == 'isolate' else 'ingress'}")[:63].rstrip("-")
    meta = {
        "name": name,
        "namespace": wl.namespace,
        "labels": {"app.kubernetes.io/managed-by": "clarikube"},
        "annotations": {
            "clarikube.io/reason": (
                "Emergency containment: deny all ingress and egress"
                if mode == "isolate"
                else "Restrict ingress to pods in the same namespace"
                + (f" and namespaces {', '.join(from_namespaces)}" if from_namespaces else "")
                + " (tune to real callers)"
            )
        },
    }
    spec: dict[str, Any] = {"podSelector": {"matchLabels": labels}}
    if mode == "isolate":
        spec["policyTypes"] = ["Ingress", "Egress"]  # no rules => deny all
    else:
        spec["policyTypes"] = ["Ingress"]
        peers: list[dict[str, Any]] = [{"podSelector": {}}]
        peers += [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}} for ns in from_namespaces or []
        ]
        spec["ingress"] = [{"from": peers}]
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta, "spec": spec}


def _register_in_kustomization(repo: Path, directory: Path, filename: str) -> FileChange | None:
    """Append a new file to ``resources`` of the kustomization.yaml in the same directory."""
    rel = directory / "kustomization.yaml"
    if not (repo / rel).exists():
        return None
    ef = mf.EditableFile(repo, rel)
    doc = ef.docs[0]
    resources = doc.get("resources")
    if not isinstance(resources, list) or filename in resources:
        return None
    resources.append(filename)
    return FileChange(path=str(rel), before=ef.original, after=ef.render())


def _namespace_dir(repo: Path, namespace: str) -> Path | None:
    """Directory holding most manifests of a namespace (where new objects for it should go)."""
    counts: dict[Path, int] = {}
    for d in mf.scan(repo):
        if d.namespace == namespace:
            counts[d.path.parent] = counts.get(d.path.parent, 0) + 1
    return max(counts, key=lambda p: (counts[p], -len(p.parts))) if counts else None


def _helm_release(snap: Snapshot, wl: WorkloadRef) -> str | None:
    spec = snap.spec_of(wl)
    labels = dict(spec.labels) if spec else {}
    for p in snap.pods_of(wl)[:1]:
        labels = {**p.labels, **labels}
    return labels.get("app.kubernetes.io/instance")


class _Edit:
    """One document being edited inside a (shared) opened file."""

    def __init__(self, ef: mf.EditableFile, index: int) -> None:
        self.ef = ef
        self.index = index
        self.doc: CommentedMap = ef.docs[index]
        self.before_plain = mf.to_plain(self.doc)


class _Workspace:
    """Every file a plan touches is opened once, so several fixes in the same file end up in one change."""

    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.files: dict[str, mf.EditableFile] = {}
        self.edits: dict[tuple[str, int], _Edit] = {}
        self.no_policy: set[str] = set()  # Helm values files: not Kubernetes objects

    def edit(self, rel: Path, index: int, policy: bool = True) -> _Edit:
        key = str(rel)
        if key not in self.files:
            self.files[key] = mf.EditableFile(self.repo, rel)
        if not policy:
            self.no_policy.add(key)
        if (key, index) not in self.edits:
            self.edits[(key, index)] = _Edit(self.files[key], index)
        return self.edits[(key, index)]

    def changes(self, first: str | None = None) -> list[FileChange]:
        out: list[FileChange] = []
        for key in sorted(self.files, key=lambda k: (k != first, k)):
            ef = self.files[key]
            after = ef.render()
            if after == ef.original:
                continue
            policy: list[PolicyResult] = []
            if key not in self.no_policy:
                for (k, _i), e in self.edits.items():
                    if k == key:
                        policy += compare(e.before_plain, mf.to_plain(e.doc))
            out.append(FileChange(path=key, before=ef.original, after=after, policy=policy))
        return out


def _helm_edits(
    ws: _Workspace, snap: Snapshot, wl: WorkloadRef, hints: list[RemediationHint], applied: list[str], notes: list[str]
) -> None:
    repo = ws.repo
    release = _helm_release(snap, wl)
    if not release:
        raise RemediationError(
            f"no manifest for {wl.kind} {wl.namespace}/{wl.name} in the GitOps repo, and it has no "
            "app.kubernetes.io/instance label to find Helm values by"
        )
    targets = helm.locate_values(repo, release, wl.namespace)
    if not targets:
        raise RemediationError(
            f"{wl.key} looks Helm-managed (release {release!r}) but no values for it were found in the repo "
            "(looked for Argo CD Applications, Flux HelmReleases and <release>/values*.yaml)"
        )

    def open_target(t: helm.ValuesTarget) -> tuple[_Edit, CommentedMap]:
        e = ws.edit(t.path, t.index, policy=False)
        return e, helm.values_root(e.ef, t)

    for h in hints:
        p = h.params
        matches: list[tuple[helm.ValuesTarget, helm.KeyPath, str]] = []
        for t in targets:
            _, values = open_target(t)
            if h.kind in ("set-memory-limit", "set-memory-request"):
                section = "limits" if h.kind == "set-memory-limit" else "requests"
                matches += [(t, kp, "") for kp in helm.memory_paths(values, section, p.get("current"))]
            elif h.kind == "set-image":
                matches += [(t, kp, how) for kp, how in helm.image_paths(values, p.get("current", ""))]
        if not matches:
            raise RemediationError(
                f"{h.kind}: release {release!r} values don't contain the live value "
                f"({p.get('current') or 'unknown'}); the chart may use a default — set it explicitly first"
            )
        if len(matches) > 1:
            where = ", ".join(f"{t.describe()}:{helm.fmt(kp)}" for t, kp, _ in matches[:5])
            raise RemediationError(f"{h.kind}: ambiguous, the live value appears in several places: {where}")
        t, kp, how = matches[0]
        _, values = open_target(t)
        new = p["proposed"].rpartition(":")[2] if h.kind == "set-image" and how == "tag" else p["proposed"]
        old = helm.set_in(values, kp, new)
        applied.append(f"Helm values ({t.source}) {t.describe()}: {helm.fmt(kp)} {old} → {new}")
    notes.append(
        f"Edited Helm values of release {release!r}; the chart renders the final manifest — check the "
        "rendered diff in your CD tool (e.g. Argo CD app diff) before merging."
    )


def _service_internal(ws: _Workspace, wl: WorkloadRef, names: list[str], applied: list[str], manual: list[str]) -> None:
    repo = ws.repo
    for name in names:
        docs = mf.locate(repo, WorkloadRef(kind="Service", namespace=wl.namespace, name=name))
        if len(docs) != 1:
            manual.append(
                f"Service {wl.namespace}/{name} is {'not in' if not docs else 'ambiguous in'} the GitOps repo "
                "(often generated by an operator or chart): change its type there, e.g. the operator's listener/"
                "service config, to ClusterIP / internal."
            )
            continue
        e = ws.edit(docs[0].path, docs[0].index)
        spec = mf.ensure_map(e.doc, "spec")
        old = spec.get("type", "ClusterIP")
        spec["type"] = "ClusterIP"
        for k in (
            "loadBalancerSourceRanges",
            "loadBalancerClass",
            "loadBalancerIP",
            "externalTrafficPolicy",
            "allocateLoadBalancerNodePorts",
            "externalIPs",
        ):
            spec.pop(k, None)
        for port in spec.get("ports") or []:
            if isinstance(port, dict):
                port.pop("nodePort", None)
        if old != "ClusterIP":
            applied.append(f"Service {name}: type {old} → ClusterIP")


def build(
    repo: Path,
    snap: Snapshot,
    wl: WorkloadRef,
    hints: list[RemediationHint],
) -> RemediationResult:
    automatable = [h for h in hints if h.kind in AUTOMATABLE]
    manual = [h.summary for h in hints if h.kind not in AUTOMATABLE]
    applied: list[str] = []
    notes: list[str] = []
    ws = _Workspace(repo)
    if not automatable:
        return RemediationResult(changes=[], applied=[], manual=manual, notes=[])

    candidates = mf.locate(repo, wl)
    if len(candidates) > 1:
        paths = ", ".join(f"{c.path}#{c.index}" for c in candidates)
        raise RemediationError(f"ambiguous: multiple manifests match {wl.key}: {paths}")
    target = candidates[0] if candidates else None
    # Hints that name another resource (e.g. a Strimzi KafkaNodePool) edit that resource's manifest.
    other: dict[tuple[str, str], list[RemediationHint]] = {}
    for h in automatable:
        if h.kind in FIELD_KINDS and h.params.get("target_kind") and h.params.get("target_name"):
            other.setdefault((h.params["target_kind"], h.params["target_name"]), []).append(h)
    for (tkind, tname), group in other.items():
        tref = WorkloadRef(kind=tkind, namespace=wl.namespace, name=tname)
        docs = mf.locate(repo, tref)
        if len(docs) != 1:
            raise RemediationError(f"{'no' if not docs else 'ambiguous'} manifest for {tref.key} in the GitOps repo")
        e = ws.edit(docs[0].path, docs[0].index)
        _apply_field_edits(e.doc, snap, group, applied, notes)
    targeted = {id(h) for g in other.values() for h in g}
    field_hints = [h for h in automatable if h.kind in FIELD_KINDS and id(h) not in targeted]
    main: _Edit | None = None
    if field_hints:
        if target is None:
            unsupported = [h.kind for h in field_hints if h.kind not in HELM_KINDS]
            if unsupported:
                raise RemediationError(
                    f"no manifest for {wl.kind} {wl.namespace}/{wl.name} in the GitOps repo; "
                    f"{', '.join(unsupported)} need the manifest (Helm values support: {', '.join(sorted(HELM_KINDS))})"
                )
            _helm_edits(ws, snap, wl, field_hints, applied, notes)
        else:
            main = ws.edit(target.path, target.index)
            if not main.ef.style_preserved:
                notes.append(f"{target.path}: YAML indentation style not recognised; formatting may change.")
            if target.namespace_source == "none":
                notes.append(f"{target.path} has no namespace (none in metadata or kustomization); matched by name.")
            _apply_field_edits(main.doc, snap, field_hints, applied, notes)

    new_dir = target.path.parent if target else _namespace_dir(repo, wl.namespace)
    new_files: list[FileChange] = []
    for h in automatable:
        p = h.params
        try:
            if h.kind in ("restrict-ingress", "isolate-workload", "add-pdb"):
                if new_dir is None:
                    raise RemediationError(f"no directory for namespace {wl.namespace} in the GitOps repo")
                if p.get("selector"):
                    labels = _parse_selector(p["selector"])
                elif main is not None:
                    labels = _selector_labels(main.doc, snap, wl)
                else:
                    pods = snap.pods_of(wl)
                    labels = {k: v for k, v in pods[0].labels.items() if k not in _VOLATILE_LABELS} if pods else {}
                if not labels:
                    raise RemediationError("cannot determine pod labels for the selector")
                if h.kind == "add-pdb":
                    obj = _pdb(
                        p.get("name") or f"{wl.name}-pdb", wl.namespace, labels, int(p.get("max_unavailable") or 1)
                    )
                    applied.append(
                        f"new PodDisruptionBudget {obj['metadata']['name']} (maxUnavailable "
                        f"{obj['spec']['maxUnavailable']})"
                    )
                    notes.append(
                        "A PDB blocks node drains while a member is already down; that is intended "
                        "for quorum systems, but tell whoever runs cluster upgrades."
                    )
                else:
                    mode = "isolate" if h.kind == "isolate-workload" else "ingress"
                    from_ns = [n for n in (p.get("from_namespaces") or "").split(",") if n]
                    obj = _netpol(wl, labels, mode, from_ns, p.get("name"))
                    applied.append(f"new NetworkPolicy {obj['metadata']['name']} ({mode})")
                    if mode == "ingress":
                        notes.append(
                            "The ingress policy allows pods in the same namespace"
                            + (f" and namespaces {', '.join(from_ns)}" if from_ns else "")
                            + "; monitoring scrapers or ingress controllers in other namespaces will be blocked "
                            "unless added."
                        )
                    else:
                        notes.append(
                            "Isolation blocks ALL traffic including DNS and health checks from outside: the workload "
                            "will be unreachable. Intended for containment during an incident."
                        )
                rel = str(new_dir / f"{obj['metadata']['name']}.yaml")
                if (repo / rel).exists():
                    raise RemediationError(f"{rel} already exists")
                new_files.append(FileChange(path=rel, before=None, after=mf.dump_new(obj)))
                kust = _register_in_kustomization(repo, new_dir, Path(rel).name)
                if kust:
                    # several new files in one plan: chain edits on the same kustomization
                    prev = next((c for c in new_files if c.path == kust.path), None)
                    if prev:
                        new_files.remove(prev)
                        kust = FileChange(
                            path=kust.path,
                            before=prev.before,
                            after=prev.after.rstrip("\n") + f"\n- {Path(rel).name}\n",
                        )
                    new_files.append(kust)
                    applied.append(f"registered {Path(rel).name} in {kust.path}")
            elif h.kind == "make-service-internal":
                names = [n for n in (p.get("services") or "").split(",") if n]
                _service_internal(ws, wl, names, applied, manual)
        except (KeyError, ValueError) as e:
            raise RemediationError(f"{h.kind}: {e}") from e

    changes = ws.changes(first=str(target.path) if target else None)
    edited = {c.path for c in changes}
    changes += [c for c in new_files if c.path not in edited]
    return RemediationResult(changes=changes, applied=applied, manual=manual, notes=notes)


def _apply_field_edits(
    doc: CommentedMap, snap: Snapshot, hints: list[RemediationHint], applied: list[str], notes: list[str]
) -> None:
    for h in hints:
        p = h.params
        try:
            if h.kind == "set-memory-limit":
                applied.append(_set_limit(doc, p["container"], "limits", "memory", p["proposed"]))
                req = (_resources_owner(doc, p["container"]).get("resources") or {}).get("requests") or {}
                if req.get("memory") and quantity.parse(str(req["memory"])) > quantity.parse(p["proposed"]):
                    applied.append(_set_limit(doc, p["container"], "requests", "memory", p["proposed"]))
                if p.get("jvm"):
                    notes.append("JVM heap left unchanged; keep it at or below 50-75% of the new limit.")
            elif h.kind == "set-memory-request":
                applied.append(_set_limit(doc, p["container"], "requests", "memory", p["proposed"]))
                lim = (_resources_owner(doc, p["container"]).get("resources") or {}).get("limits") or {}
                if lim.get("memory") and quantity.parse(str(lim["memory"])) < quantity.parse(p["proposed"]):
                    notes.append("memory limit is below the new request; adjust it too")
            elif h.kind == "set-image":
                c = mf.container(doc, p["container"])
                old = c.get("image")
                c["image"] = p["proposed"]
                applied.append(f"{p['container']}: image {old} → {p['proposed']}")
            elif h.kind == "rollback-template":
                rs = next((r for r in snap.replicasets if r.name == p["replicaset"]), None)
                if rs is None:
                    raise RemediationError(f"previous ReplicaSet {p['replicaset']} not found")
                for prev in rs.containers:
                    if prev.init:
                        continue
                    c = mf.container(doc, prev.name)
                    if prev.image and c.get("image") != prev.image:
                        applied.append(f"{prev.name}: image {c.get('image')} → {prev.image}")
                        c["image"] = prev.image
                    for section, res, val in (
                        ("requests", "cpu", prev.resources.cpu_request),
                        ("limits", "cpu", prev.resources.cpu_limit),
                        ("requests", "memory", prev.resources.memory_request),
                        ("limits", "memory", prev.resources.memory_limit),
                    ):
                        cur = ((c.get("resources") or {}).get(section) or {}).get(res)
                        if val and str(cur) != val:
                            applied.append(_set_limit(doc, prev.name, section, res, val))
                notes.append(
                    f"Reverted image/resources to revision {p['to_revision']}; other template fields "
                    "(env, args, probes) are not compared in v1 — review the original change too."
                )
            elif h.kind == "harden-security-context":
                a, n = _harden(doc)
                applied += a
                notes += n
            elif h.kind == "set-modsecurity-blocking":
                if doc.get("kind") != "ConfigMap":
                    raise RemediationError("set-modsecurity-blocking edits the ingress-nginx controller ConfigMap")
                data = mf.ensure_map(doc, "data")
                snippet = str(data.get("modsecurity-snippet") or "")
                if re.search(r"^\s*SecRuleEngine\s+\w+", snippet, re.M | re.I):
                    snippet = re.sub(r"^(\s*)SecRuleEngine\s+\w+", r"\1SecRuleEngine On", snippet, flags=re.M | re.I)
                else:
                    snippet = "SecRuleEngine On\n" + snippet
                data["modsecurity-snippet"] = LiteralScalarString(snippet if snippet.endswith("\n") else snippet + "\n")
                applied.append("ingress-nginx: ModSecurity SecRuleEngine → On (blocking)")
                notes.append(
                    "Blocking mode can reject legitimate requests that match a rule (false positives). Review the "
                    "ModSecurity audit log in DetectionOnly first and roll out to staging before production."
                )
            elif h.kind == "set-fluentbit-option":
                if doc.get("kind") != "ConfigMap":
                    raise RemediationError("set-fluentbit-option edits the Fluent Bit ConfigMap")
                data = mf.ensure_map(doc, "data")
                if "fluent-bit.conf" not in data:
                    raise RemediationError(
                        "only classic fluent-bit.conf configs are edited automatically (YAML config: set it by hand)"
                    )
                edited = 0
                for key_name in sorted(str(k) for k in data):
                    if not key_name.endswith(".conf") or "parser" in key_name:
                        continue
                    new_text, count = fluentbit.set_option_classic(
                        str(data[key_name]), p["section"], p["key"], p["value"]
                    )
                    if count:
                        data[key_name] = LiteralScalarString(new_text)
                        edited += count
                if edited == 0:
                    raise RemediationError(f"no [{p['section']}] section needed {p['key']} changed")
                applied.append(f"Fluent Bit: {p['key']} {p['value']} in {edited} [{p['section']}] section(s)")
                if p["key"].lower() == "retry_limit":
                    notes.append(
                        "Unlimited retries keep chunks until delivery; pair with storage.type filesystem so a long "
                        "outage of the destination does not fill memory."
                    )
            elif h.kind == "add-toleration":
                ps = mf.pod_spec(doc)
                if not isinstance(ps.get("tolerations"), list):
                    ps["tolerations"] = CommentedSeq()
                tol = ps["tolerations"]
                if not any(isinstance(t, dict) and t.get("operator") == "Exists" and not t.get("key") for t in tol):
                    tol.append(CommentedMap(operator="Exists"))
                    applied.append("tolerations += {operator: Exists} (runs on every node, including tainted ones)")
            elif h.kind == "set-kafka-config":
                if doc.get("kind") != "Kafka":
                    raise RemediationError("set-kafka-config only edits a Strimzi Kafka resource")
                cfg = mf.ensure_map(mf.ensure_map(mf.ensure_map(doc, "spec"), "kafka"), "config")
                old = cfg.get(p["key"])
                cfg[p["key"]] = int(p["proposed"]) if p["proposed"].isdigit() else p["proposed"]
                applied.append(f"Kafka config {p['key']}: {old} → {p['proposed']}")
                notes.append(
                    "Strimzi rolls the brokers one at a time to apply broker config changes; topics created "
                    "with an explicit min.insync.replicas keep their own value (check with kafka-configs)."
                )
        except KeyError as e:
            raise RemediationError(f"{h.kind}: {e}") from e
