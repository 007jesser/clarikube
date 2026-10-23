"""Turn remediation hints into concrete manifest edits in a GitOps repo.

Automatable kinds edit or add files. Everything else is returned as manual guidance — kubepilot
never creates secrets, rotates credentials or edits RBAC on its own.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml.comments import CommentedMap, CommentedSeq

from kubepilot import quantity
from kubepilot.gitops import manifests as mf
from kubepilot.models import RemediationHint, WorkloadRef
from kubepilot.policy import PolicyResult, compare
from kubepilot.source.base import Snapshot

AUTOMATABLE = {
    "set-memory-limit",
    "set-memory-request",
    "set-image",
    "rollback-template",
    "harden-security-context",
    "restrict-ingress",
    "isolate-workload",
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

    def diff(self) -> str:
        a = (self.before or "").splitlines(keepends=True)
        b = self.after.splitlines(keepends=True)
        return "".join(
            difflib.unified_diff(
                a,
                b,
                fromfile="/dev/null" if self.before is None else f"a/{self.path}",
                tofile=f"b/{self.path}",
            )
        )


@dataclass
class RemediationResult:
    changes: list[FileChange]
    applied: list[str]  # summaries of edits applied
    manual: list[str]  # guidance the human must act on
    notes: list[str]  # caveats the reviewer must check


# ---------------------------------------------------------------- edit helpers


def _set_limit(doc: CommentedMap, cname: str, section: str, res: str, value: str) -> str:
    c = mf.container(doc, cname)
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


def _netpol(wl: WorkloadRef, labels: dict[str, str], mode: str) -> dict[str, Any]:
    name = f"kubepilot-{wl.name}-{'isolate' if mode == 'isolate' else 'ingress'}"[:63].rstrip("-")
    meta = {
        "name": name,
        "namespace": wl.namespace,
        "labels": {"app.kubernetes.io/managed-by": "kubepilot"},
        "annotations": {
            "kubepilot.io/reason": (
                "Emergency containment: deny all ingress and egress"
                if mode == "isolate"
                else "Restrict ingress to pods in the same namespace (tune to real callers)"
            )
        },
    }
    spec: dict[str, Any] = {"podSelector": {"matchLabels": labels}}
    if mode == "isolate":
        spec["policyTypes"] = ["Ingress", "Egress"]  # no rules => deny all
    else:
        spec["policyTypes"] = ["Ingress"]
        spec["ingress"] = [{"from": [{"podSelector": {}}]}]
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


# ---------------------------------------------------------------- main entry


def build(
    repo: Path,
    snap: Snapshot,
    wl: WorkloadRef,
    hints: list[RemediationHint],
) -> RemediationResult:
    automatable = [h for h in hints if h.kind in AUTOMATABLE]
    manual = [h.summary for h in hints if h.kind not in AUTOMATABLE]
    if not automatable:
        return RemediationResult(changes=[], applied=[], manual=manual, notes=[])

    candidates = mf.locate(repo, wl)
    if not candidates:
        raise RemediationError(
            f"no manifest for {wl.kind} {wl.namespace}/{wl.name} found in the GitOps repo "
            "(v1 supports plain manifests and Kustomize; Helm-templated files are not editable)"
        )
    if len(candidates) > 1:
        paths = ", ".join(f"{c.path}#{c.index}" for c in candidates)
        raise RemediationError(f"ambiguous: multiple manifests match {wl.key}: {paths}")
    target = candidates[0]
    ef = mf.EditableFile(repo, target.path)
    doc: CommentedMap = ef.docs[target.index]
    before_plain = mf.to_plain(doc)

    applied: list[str] = []
    notes: list[str] = []
    if not ef.style_preserved:
        notes.append(f"{target.path}: YAML indentation style not recognised; formatting may change in the diff.")
    if target.namespace_source == "none":
        notes.append(f"{target.path} has no namespace (none in metadata or kustomization); matched by name only.")
    new_files: list[FileChange] = []

    for h in automatable:
        p = h.params
        try:
            if h.kind == "set-memory-limit":
                applied.append(_set_limit(doc, p["container"], "limits", "memory", p["proposed"]))
                req = (mf.container(doc, p["container"]).get("resources") or {}).get("requests") or {}
                if req.get("memory") and quantity.parse(str(req["memory"])) > quantity.parse(p["proposed"]):
                    applied.append(_set_limit(doc, p["container"], "requests", "memory", p["proposed"]))
            elif h.kind == "set-memory-request":
                applied.append(_set_limit(doc, p["container"], "requests", "memory", p["proposed"]))
                lim = (mf.container(doc, p["container"]).get("resources") or {}).get("limits") or {}
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
            elif h.kind in ("restrict-ingress", "isolate-workload"):
                mode = "isolate" if h.kind == "isolate-workload" else "ingress"
                np = _netpol(wl, _selector_labels(doc, snap, wl), mode)
                rel = str(target.path.parent / f"{np['metadata']['name']}.yaml")
                if (repo / rel).exists():
                    raise RemediationError(f"{rel} already exists")
                new_files.append(FileChange(path=rel, before=None, after=mf.dump_new(np)))
                applied.append(f"new NetworkPolicy {np['metadata']['name']} ({mode})")
                kust = _register_in_kustomization(repo, target.path.parent, Path(rel).name)
                if kust:
                    new_files.append(kust)
                    applied.append(f"registered {Path(rel).name} in {kust.path}")
                if mode == "ingress":
                    notes.append(
                        "The ingress policy allows all pods in the same namespace; tighten 'from' to real callers."
                    )
                else:
                    notes.append(
                        "Isolation blocks ALL traffic including DNS and health checks from outside: the workload "
                        "will be unreachable. Intended for containment during an incident."
                    )
        except KeyError as e:
            raise RemediationError(f"{h.kind}: {e}") from e

    changes: list[FileChange] = []
    after_text = ef.render()
    if after_text != ef.original:
        changes.append(
            FileChange(
                path=str(target.path),
                before=ef.original,
                after=after_text,
                policy=compare(before_plain, mf.to_plain(doc)),
            )
        )
    changes.extend(new_files)
    return RemediationResult(changes=changes, applied=applied, manual=manual, notes=notes)
