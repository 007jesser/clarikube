"""Cluster operations packs: findings about the platform tooling around workloads.

Gateway API / Traefik routes, GitOps controllers (Argo CD, Flux), secret sync (External Secrets, Sealed Secrets),
autoscaling (HPA, KEDA, Karpenter, Cluster Autoscaler), storage (StorageClasses, Longhorn, Rook Ceph), policy
(Kyverno, PolicyReports, admission denials), backups (Velero), monitoring (Prometheus operator, Alertmanager
alerts), node versions, LoadBalancer provisioning and service mesh injection.

All status fields and condition types were checked against the projects' sources (docs/platform-notes.md).
Each function is pure over the snapshot and returns findings with evidence; nothing here reads a secret value.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import timedelta
from typing import Any

from kubepilot.engine import selectors
from kubepilot.models import (
    Condition,
    CustomResource,
    Evidence,
    Finding,
    Pod,
    RemediationHint,
    Severity,
    WorkloadRef,
)
from kubepilot.normalize import ts
from kubepilot.sanitize import clean
from kubepilot.source.base import Snapshot


def _fid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:10]


def _ref(cr: CustomResource) -> WorkloadRef:
    return WorkloadRef(kind=cr.kind, namespace=cr.namespace, name=cr.name)


def _crs(snap: Snapshot, *kinds: str, group: str | None = None) -> list[CustomResource]:
    return [c for c in snap.custom_resources if c.kind in kinds and (group is None or c.group == group)]


def _cond(conds: Iterable[Condition], ctype: str) -> Condition | None:
    return next((c for c in conds if c.type == ctype), None)


def _raw_conds(items: Any) -> list[Condition]:
    return [
        Condition(
            type=str(c.get("type", "")),
            status=str(c.get("status", "")),
            reason=c.get("reason"),
            message=c.get("message"),
        )
        for c in items or []
        if isinstance(c, dict)
    ]


def _cev(c: Condition) -> Evidence:
    return Evidence(source="status", detail=f"{c.type}={c.status} {c.reason or ''}: {clean(c.message, 260)}".strip())


def _finding(
    ref: WorkloadRef,
    code: str,
    title: str,
    sev: Severity,
    expl: str,
    *,
    category: str = "reliability",
    evidence: list[Evidence] | None = None,
    hints: list[RemediationHint] | None = None,
) -> Finding:
    return Finding(
        id=_fid(ref.key, code),
        workload=ref,
        category=category,  # type: ignore[arg-type]
        title=title,
        severity=sev,
        explanation=expl,
        evidence=evidence or [],
        remediations=hints or [],
    )


def _ready_pod(p: Pod) -> bool:
    app = p.app_containers
    return p.phase == "Running" and bool(app) and all(c.ready for c in app)


def _service_backend_findings(snap: Snapshot, ref: WorkloadRef, ns: str, svc_name: str, where: str) -> list[Finding]:
    svc = next((s for s in snap.services if s.namespace == ns and s.name == svc_name), None)
    if svc is None:
        return [
            _finding(
                ref,
                f"missing-{svc_name}",
                f"{ref.kind} {ref.namespace}/{ref.name} routes {where} to missing Service {svc_name}",
                Severity.HIGH,
                "Requests for this route fail because the backend Service does not exist.",
            )
        ]
    pods = [
        p
        for p in snap.pods
        if p.namespace == ns and svc.selector and all(p.labels.get(k) == v for k, v in svc.selector.items())
    ]
    if svc.selector and not any(_ready_pod(p) for p in pods):
        owners = sorted({p.workload.key for p in pods})
        return [
            _finding(
                ref,
                f"noready-{svc_name}",
                f"{ref.kind} {ref.namespace}/{ref.name}: {where} has no ready backend ({svc_name})",
                Severity.HIGH,
                f"Users get 503 errors: Service {svc_name} selects {len(pods)} pod(s) and none is ready."
                + (f" Diagnose {', '.join(owners)}." if owners else " No pod matches its selector."),
                hints=[
                    RemediationHint(
                        kind="investigate-workload",
                        params={"workload": owners[0]},
                        summary=f"Run diagnose_workload on {owners[0]}",
                    )
                ]
                if owners
                else [],
            )
        ]
    return []


# ---------------------------------------------------------------- Gateway API and Traefik


def gateway_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for gw in _crs(snap, "Gateway", group="gateway.networking.k8s.io"):
        ref = _ref(gw)
        bad = [c for c in gw.conditions if c.type in ("Accepted", "Programmed") and c.status == "False"]
        if bad:
            out.append(
                _finding(
                    ref,
                    "gw",
                    f"Gateway {gw.namespace}/{gw.name} is not serving traffic",
                    Severity.CRITICAL,
                    "The Gateway is not Accepted/Programmed by its controller, so none of its listeners "
                    "receive traffic (often: no address assigned, invalid GatewayClass, controller down).",
                    evidence=[_cev(c) for c in bad],
                )
            )
        for lst in gw.status.get("listeners") or []:
            for c in _raw_conds(lst.get("conditions")):
                if c.type in ("ResolvedRefs", "Programmed") and c.status == "False":
                    out.append(
                        _finding(
                            ref,
                            f"listener-{lst.get('name')}",
                            f"Gateway {gw.namespace}/{gw.name}: listener {lst.get('name')} is broken",
                            Severity.HIGH,
                            "The listener cannot be programmed; with ResolvedRefs=False this usually "
                            "means its TLS certificate Secret is missing or not permitted.",
                            evidence=[_cev(c)],
                        )
                    )
    for rt in _crs(snap, "HTTPRoute", group="gateway.networking.k8s.io"):
        ref = _ref(rt)
        for parent in rt.status.get("parents") or []:
            pname = (parent.get("parentRef") or {}).get("name", "?")
            for c in _raw_conds(parent.get("conditions")):
                if c.type == "Accepted" and c.status == "False":
                    out.append(
                        _finding(
                            ref,
                            f"accepted-{pname}",
                            f"HTTPRoute {rt.namespace}/{rt.name} is not attached to Gateway {pname}",
                            Severity.HIGH,
                            "The route is ignored by the Gateway (e.g. NoMatchingParent: wrong section or "
                            "hostname; NotAllowedByListeners: the listener does not allow routes from this "
                            "namespace). Traffic for it is not routed.",
                            evidence=[_cev(c)],
                        )
                    )
                if c.type == "ResolvedRefs" and c.status == "False":
                    out.append(
                        _finding(
                            ref,
                            f"refs-{pname}",
                            f"HTTPRoute {rt.namespace}/{rt.name}: backend reference cannot be resolved",
                            Severity.HIGH,
                            "A backendRef points at a Service that does not exist (BackendNotFound) or in "
                            "another namespace without a ReferenceGrant (RefNotPermitted).",
                            evidence=[_cev(c)],
                        )
                    )
        for rule in rt.spec.get("rules") or []:
            for b in rule.get("backendRefs") or []:
                if (b.get("kind") or "Service") == "Service" and b.get("name") and not b.get("namespace"):
                    out += _service_backend_findings(
                        snap, ref, rt.namespace, str(b["name"]), ",".join(rt.spec.get("hostnames") or []) or "*"
                    )
    for ir in _crs(snap, "IngressRoute", group="traefik.io"):
        ref = _ref(ir)
        mws = {(m.namespace, m.name) for m in _crs(snap, "Middleware", group="traefik.io")}
        for route in ir.spec.get("routes") or []:
            match = clean(str(route.get("match") or ""), 120)
            for svc in route.get("services") or []:
                if (svc.get("kind") or "Service") == "Service" and svc.get("name"):
                    out += _service_backend_findings(
                        snap, ref, str(svc.get("namespace") or ir.namespace), str(svc["name"]), match
                    )
            for mw in route.get("middlewares") or []:
                key = (str(mw.get("namespace") or ir.namespace), str(mw.get("name")))
                if key not in mws:
                    out.append(
                        _finding(
                            ref,
                            f"mw-{key[1]}",
                            f"IngressRoute {ir.namespace}/{ir.name} uses missing Middleware {key[1]}",
                            Severity.HIGH,
                            "Traefik cannot build this router while the Middleware is missing, so the "
                            "route is not served as intended (auth, redirects or headers it adds are "
                            "absent).",
                            category="config",
                        )
                    )
    return out


# ---------------------------------------------------------------- GitOps controllers


def gitops_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for app in _crs(snap, "Application", group="argoproj.io"):
        ref = _ref(app)
        health = str((app.status.get("health") or {}).get("status") or "")
        sync = str((app.status.get("sync") or {}).get("status") or "")
        op = app.status.get("operationState") or {}
        phase = str(op.get("phase") or "")
        errs = [
            c
            for c in _raw_conds(app.status.get("conditions"))
            if c.type in ("ComparisonError", "SyncError", "InvalidSpecError", "UnknownError")
        ]
        ev = [
            Evidence(source="argocd", detail=f"sync={sync or '?'} health={health or '?'} lastOperation={phase or '-'}")
        ]
        if op.get("message") and phase in ("Failed", "Error"):
            ev.append(Evidence(source="argocd", detail=f"operation: {clean(str(op['message']), 260)}"))
        ev += [Evidence(source="argocd", detail=f"{c.type}: {clean(c.message, 260)}") for c in errs]
        dest = (app.spec.get("destination") or {}).get("namespace") or "?"
        if phase in ("Failed", "Error") or errs:
            out.append(
                _finding(
                    ref,
                    "sync",
                    f"Argo CD app {app.name}: sync is failing",
                    Severity.HIGH,
                    f"Argo CD cannot apply Git to namespace {dest}: merged changes (including fixes) are not "
                    "reaching the cluster.",
                    evidence=ev,
                )
            )
        elif health in ("Degraded", "Missing"):
            out.append(
                _finding(
                    ref,
                    "health",
                    f"Argo CD app {app.name} is {health}",
                    Severity.HIGH,
                    f"Resources of this application in {dest} are {health.lower()}; diagnose the workloads "
                    "in that namespace.",
                    evidence=ev,
                )
            )
        elif sync == "OutOfSync" and not (app.spec.get("syncPolicy") or {}).get("automated"):
            out.append(
                _finding(
                    ref,
                    "drift",
                    f"Argo CD app {app.name} is OutOfSync (manual sync)",
                    Severity.LOW,
                    "The cluster differs from Git and auto-sync is off; someone has to sync it (or the "
                    "drift is a manual change that Git will overwrite).",
                    category="config",
                    evidence=ev,
                )
            )
    flux_kinds = ("Kustomization", "HelmRelease", "GitRepository", "HelmRepository", "OCIRepository")
    for cr in snap.custom_resources:
        if cr.kind not in flux_kinds or not cr.group.endswith("toolkit.fluxcd.io"):
            continue
        ref = _ref(cr)
        if cr.spec.get("suspend") is True:
            out.append(
                _finding(
                    ref,
                    "suspended",
                    f"Flux {cr.kind} {cr.namespace}/{cr.name} is suspended",
                    Severity.LOW,
                    "Reconciliation is paused: changes in Git are not applied until it is resumed (`flux resume`).",
                    category="config",
                )
            )
            continue
        ready = _cond(cr.conditions, "Ready")
        stalled = _cond(cr.conditions, "Stalled")
        if (ready and ready.status == "False") or (stalled and stalled.status == "True"):
            what = "fetch from its source" if cr.kind.endswith("Repository") else "apply to the cluster"
            out.append(
                _finding(
                    ref,
                    "ready",
                    f"Flux {cr.kind} {cr.namespace}/{cr.name} is failing",
                    Severity.HIGH,
                    f"Flux cannot {what}: merged changes are not reaching the cluster.",
                    evidence=[_cev(c) for c in (ready, stalled) if c is not None],
                )
            )
    return out


# ---------------------------------------------------------------- secrets


def secret_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for es in _crs(snap, "ExternalSecret", group="external-secrets.io"):
        ready = _cond(es.conditions, "Ready")
        if ready and ready.status == "False":
            target = (es.spec.get("target") or {}).get("name") or es.name
            out.append(
                _finding(
                    _ref(es),
                    "sync",
                    f"ExternalSecret {es.namespace}/{es.name} cannot sync",
                    Severity.HIGH,
                    f"Secret {target} is not created or updated from the secret store; pods that use it "
                    "fail to start or keep stale credentials.",
                    evidence=[_cev(ready)],
                    hints=[
                        RemediationHint(
                            kind="check-secret-store", summary="Check the SecretStore credentials and the remote key"
                        )
                    ],
                )
            )
    for st in _crs(snap, "SecretStore", "ClusterSecretStore", group="external-secrets.io"):
        ready = _cond(st.conditions, "Ready")
        if ready and ready.status == "False":
            out.append(
                _finding(
                    _ref(st),
                    "store",
                    f"{st.kind} {st.name} is not ready",
                    Severity.HIGH,
                    "External Secrets cannot authenticate to the provider (InvalidStoreConfiguration / "
                    "ValidationFailed): every ExternalSecret using it stops syncing.",
                    evidence=[_cev(ready)],
                )
            )
    for ss in _crs(snap, "SealedSecret", group="bitnami.com"):
        synced = _cond(ss.conditions, "Synced")
        if synced and synced.status == "False":
            out.append(
                _finding(
                    _ref(ss),
                    "unseal",
                    f"SealedSecret {ss.namespace}/{ss.name} cannot be decrypted",
                    Severity.HIGH,
                    "The controller cannot unseal it (sealed with another controller key, or for another "
                    "namespace/name), so the Secret is missing or stale.",
                    evidence=[_cev(synced)],
                )
            )
    return out


def secret_root_causes(
    snap: Snapshot, wl: WorkloadRef, own: list[Finding], secret_findings_: list[Finding]
) -> list[Finding]:
    """Missing Secret X for a workload + failing ExternalSecret/SealedSecret producing X → name the real cause."""
    missing = {
        (h.params.get("namespace"), h.params.get("name"))
        for f in own
        for h in f.remediations
        if h.kind == "create-missing-reference" and h.params.get("kind") == "secret"
    }
    out: list[Finding] = []
    for ns, name in missing:
        for cr in _crs(snap, "ExternalSecret", "SealedSecret"):
            target = ((cr.spec.get("target") or {}).get("name") if cr.kind == "ExternalSecret" else None) or cr.name
            if cr.namespace != ns or target != name:
                continue
            failing = [f for f in secret_findings_ if f.workload == _ref(cr)]
            status = "is failing to sync" if failing else "exists but has not produced it yet"
            ev = [
                Evidence(source="dependency", detail=f"{wl.name} needs Secret {name}, produced by {cr.kind} {cr.name}")
            ]
            ev += [e for f in failing for e in f.evidence][:3]
            out.append(
                Finding(
                    id=_fid(wl.key, "secret-root", cr.kind, cr.name),
                    workload=wl,
                    category="reliability",
                    title=f"Likely root cause: {cr.kind} {cr.namespace}/{cr.name} {status}",
                    severity=Severity.HIGH,
                    explanation=f"{wl.name} cannot start because Secret {name} is missing. It is managed by "
                    f"{cr.kind} {cr.name}, which {status}. Fix that (store credentials, remote key, sealing "
                    "key); do not create the Secret by hand.",
                    evidence=ev,
                    remediations=[
                        RemediationHint(
                            kind="investigate-secret-sync",
                            summary=f"kubectl describe {cr.kind.lower()} -n {ns} {cr.name}",
                        )
                    ],
                )
            )
    return out


# ---------------------------------------------------------------- autoscaling


def autoscaling_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for h in snap.hpas:
        ref = WorkloadRef(kind=h.target_kind or "Deployment", namespace=h.namespace, name=h.target_name)
        active = _cond(h.conditions, "ScalingActive")
        able = _cond(h.conditions, "AbleToScale")
        limited = _cond(h.conditions, "ScalingLimited")
        if active and active.status == "False" and active.reason != "ScalingDisabled":
            hint = "" if snap.metrics_available else " metrics-server does not answer, which is the usual cause."
            out.append(
                _finding(
                    ref,
                    f"hpa-metrics-{h.name}",
                    f"HPA {h.name} cannot read its metrics and is not scaling",
                    Severity.HIGH,
                    f"{h.target_kind} {h.target_name} stays at {h.current_replicas} replica(s) whatever the "
                    f"load.{hint}",
                    evidence=[_cev(active)],
                )
            )
        elif able and able.status == "False":
            out.append(
                _finding(
                    ref,
                    f"hpa-able-{h.name}",
                    f"HPA {h.name} cannot scale {h.target_name}",
                    Severity.HIGH,
                    "The HPA cannot read or update the scale subresource of its target.",
                    evidence=[_cev(able)],
                )
            )
        elif (
            h.current_replicas >= h.max_replicas > 0
            and limited
            and limited.status == "True"
            and limited.reason == "TooManyReplicas"
        ):
            pods = [p for p in snap.pods if p.workload == ref]
            unready = [p for p in pods if not _ready_pod(p)]
            out.append(
                _finding(
                    ref,
                    f"hpa-max-{h.name}",
                    f"HPA {h.name} is pinned at maxReplicas ({h.max_replicas})",
                    Severity.HIGH if unready else Severity.MEDIUM,
                    f"Load wants more than {h.max_replicas} replicas of {h.target_name}; requests beyond "
                    "that capacity queue or fail. Raise maxReplicas or make each replica handle more.",
                    category="config",
                    evidence=[_cev(limited)],
                )
            )
    for so in _crs(snap, "ScaledObject", "ScaledJob", group="keda.sh"):
        ready = _cond(so.conditions, "Ready")
        fallback = _cond(so.conditions, "Fallback")
        if ready and ready.status == "False":
            out.append(
                _finding(
                    _ref(so),
                    "keda",
                    f"KEDA {so.kind} {so.namespace}/{so.name} is not ready",
                    Severity.HIGH,
                    "KEDA cannot evaluate its triggers (scaler auth, unreachable event source or missing "
                    "target): the workload does not scale on events.",
                    evidence=[_cev(ready)],
                )
            )
        elif fallback and fallback.status == "True":
            out.append(
                _finding(
                    _ref(so),
                    "fallback",
                    f"KEDA {so.name} is running on fallback replicas",
                    Severity.MEDIUM,
                    "The scaler keeps failing, so KEDA uses the configured fallback replica count instead "
                    "of real demand.",
                    evidence=[_cev(fallback)],
                )
            )
    pending = [p for p in snap.pods if p.phase == "Pending" and p.unschedulable_message]
    for np in _crs(snap, "NodePool", group="karpenter.sh"):
        ready = _cond(np.conditions, "Ready")
        if ready and ready.status == "False":
            out.append(
                _finding(
                    _ref(np),
                    "nodepool",
                    f"Karpenter NodePool {np.name} is not ready",
                    Severity.HIGH,
                    "Karpenter will not launch nodes from this pool (NodeClass not ready or validation failed).",
                    evidence=[_cev(ready)],
                )
            )
        limits = np.spec.get("limits") or {}
        used = np.status.get("resources") or {}
        full = [r for r in ("cpu", "memory") if r in limits and r in used and _qty(used[r]) >= _qty(limits[r])]
        if full and pending:
            out.append(
                _finding(
                    _ref(np),
                    "limits",
                    f"Karpenter NodePool {np.name} reached its {'/'.join(full)} limit",
                    Severity.HIGH,
                    f"{len(pending)} pod(s) are Pending and the pool cannot grow past spec.limits.",
                    evidence=[Evidence(source="karpenter", detail=f"{r}: {used[r]} of {limits[r]}") for r in full],
                )
            )
    for nc in _crs(snap, "NodeClaim", group="karpenter.sh"):
        launched = _cond(nc.conditions, "Launched")
        if launched and launched.status == "False":
            out.append(
                _finding(
                    _ref(nc),
                    "launch",
                    f"Karpenter NodeClaim {nc.name} failed to launch",
                    Severity.HIGH,
                    "The cloud provider could not create the node (capacity, quota, subnet or instance profile).",
                    evidence=[_cev(launched)],
                )
            )
    for p in pending:
        evs = [
            e
            for e in snap.events
            if e.namespace == p.namespace
            and e.involved_name == p.name
            and e.reason in ("NotTriggerScaleUp", "FailedScaleUp")
        ]
        if evs:
            e = max(evs, key=lambda x: x.last_seen or snap.now)
            out.append(
                _finding(
                    p.workload,
                    f"ca-{p.name}",
                    f"Cluster Autoscaler will not add a node for {p.workload.name}",
                    Severity.HIGH,
                    "The autoscaler evaluated the Pending pod and decided no node group can fit it "
                    "(max size reached, or requests/selectors/taints no group satisfies).",
                    evidence=[Evidence(source="event", detail=f"{e.reason}: {clean(e.message, 260)}")],
                )
            )
    return out


def _qty(v: Any) -> float:
    from kubepilot import quantity

    try:
        return float(quantity.parse(str(v)))
    except (ValueError, ArithmeticError):
        return 0.0


# ---------------------------------------------------------------- storage


def storage_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    classes = {c.name: c for c in snap.storage_classes}
    defaults = [c for c in snap.storage_classes if c.default]
    if len(defaults) > 1:
        out.append(
            _finding(
                WorkloadRef(kind="StorageClass", namespace="", name=defaults[0].name),
                "multi-default",
                "Several StorageClasses are marked default",
                Severity.LOW,
                "PVCs without a class get whichever default the API server picks (the newest), which is "
                "rarely what was intended.",
                category="config",
                evidence=[Evidence(source="storage", detail=", ".join(c.name for c in defaults))],
            )
        )
    if snap.storage_classes:
        for c in snap.pvcs:
            if c.phase != "Pending":
                continue
            ref = WorkloadRef(kind="PersistentVolumeClaim", namespace=c.namespace, name=c.name)
            if c.storage_class and c.storage_class not in classes:
                out.append(
                    _finding(
                        ref,
                        "noclass",
                        f"PVC {c.namespace}/{c.name} uses missing StorageClass {c.storage_class}",
                        Severity.HIGH,
                        "No provisioner will ever create this volume; the pod using it stays Pending. Use an "
                        f"existing class ({', '.join(sorted(classes))}).",
                        category="config",
                    )
                )
            elif not c.storage_class and not defaults:
                out.append(
                    _finding(
                        ref,
                        "nodefault",
                        f"PVC {c.namespace}/{c.name} has no StorageClass and there is no default",
                        Severity.HIGH,
                        "The claim waits for a manually created PersistentVolume that will likely never "
                        "come. Set storageClassName or mark a default class.",
                        category="config",
                    )
                )
    for v in _crs(snap, "Volume", group="longhorn.io"):
        rob = str(v.status.get("robustness") or "")
        if rob in ("degraded", "faulted"):
            sev = Severity.CRITICAL if rob == "faulted" else Severity.MEDIUM
            out.append(
                _finding(
                    _ref(v),
                    "robustness",
                    f"Longhorn volume {v.name} is {rob}",
                    sev,
                    "faulted: no healthy replica, data is unavailable. degraded: fewer healthy replicas "
                    "than configured, one more failure may lose data.",
                    evidence=[Evidence(source="longhorn", detail=f"state={v.status.get('state')} robustness={rob}")],
                )
            )
    for cc in _crs(snap, "CephCluster", group="ceph.rook.io"):
        health = str((cc.status.get("ceph") or {}).get("health") or "")
        if health in ("HEALTH_WARN", "HEALTH_ERR"):
            msg = clean(str((cc.status.get("ceph") or {}).get("details") or ""), 260)
            out.append(
                _finding(
                    _ref(cc),
                    "ceph",
                    f"Ceph cluster {cc.namespace}/{cc.name} is {health}",
                    Severity.CRITICAL if health == "HEALTH_ERR" else Severity.MEDIUM,
                    "Ceph reports a problem (OSDs down, PGs degraded, near-full...). `ceph health detail` "
                    "in the toolbox gives the specifics.",
                    evidence=[Evidence(source="ceph", detail=msg)] if msg else [],
                )
            )
    return out


# ---------------------------------------------------------------- policy engines


_DENIED = re.compile(r"admission webhook \"?([\w.\-]+)\"? denied the request:?\s*(.*)", re.I | re.S)


def policy_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for pol in _crs(snap, "ClusterPolicy", "Policy", group="kyverno.io"):
        ready = _cond(pol.conditions, "Ready")
        if ready and ready.status == "False":
            out.append(
                _finding(
                    _ref(pol),
                    "ready",
                    f"Kyverno {pol.kind} {pol.name} is not ready",
                    Severity.MEDIUM,
                    "Kyverno could not load the policy, so it is not enforced.",
                    category="config",
                    evidence=[_cev(ready)],
                )
            )
    for rep in _crs(snap, "PolicyReport", "ClusterPolicyReport", group="wgpolicyk8s.io"):
        scope = rep.spec.get("scope") or {}
        fails = [
            r for r in rep.spec.get("results") or [] if isinstance(r, dict) and r.get("result") in ("fail", "error")
        ]
        if not fails or not scope.get("name"):
            continue
        ref = _owner(
            snap, str(scope.get("kind") or ""), str(scope.get("namespace") or rep.namespace), str(scope["name"])
        )
        sev = max(
            (_SEV.get(str(r.get("severity") or "medium"), Severity.MEDIUM) for r in fails), default=Severity.MEDIUM
        )
        out.append(
            _finding(
                ref,
                f"report-{rep.name}",
                f"{ref.kind} {ref.namespace}/{ref.name} fails {len(fails)} policy check(s)",
                sev,
                "Policy engine audit results for this resource.",
                category="security",
                evidence=[
                    Evidence(
                        source=str(r.get("source") or "policy"),
                        detail=f"{r.get('policy')}/{r.get('rule')}: {clean(str(r.get('message') or ''), 200)}",
                    )
                    for r in fails[:5]
                ],
            )
        )
    for e in snap.events:
        if e.type != "Warning" or e.reason != "FailedCreate":
            continue
        m = _DENIED.search(e.message or "")
        if not m:
            continue
        ref = _owner(snap, e.involved_kind, e.namespace, e.involved_name)
        out.append(
            _finding(
                ref,
                f"denied-{e.involved_name}",
                f"Pods of {ref.name} are blocked by admission policy",
                Severity.HIGH,
                f"The controller cannot create pods: webhook {m.group(1)} denies them. The workload "
                "runs with fewer (or zero) pods until the manifest complies or the policy is changed.",
                evidence=[Evidence(source="event", detail=clean(m.group(2) or e.message, 300))],
            )
        )
    return out


_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.LOW,
}


def _owner(snap: Snapshot, kind: str, ns: str, name: str) -> WorkloadRef:
    """Map a Pod / ReplicaSet / Job reference to its top-level workload when known."""
    if kind == "Pod":
        p = next((p for p in snap.pods if p.namespace == ns and p.name == name), None)
        if p is not None:
            return p.workload
    if kind == "ReplicaSet":
        rs = next((r for r in snap.replicasets if r.namespace == ns and r.name == name), None)
        if rs is not None and rs.owner is not None:
            return rs.owner
    return WorkloadRef(kind=kind or "Object", namespace=ns, name=name)


# ---------------------------------------------------------------- backups (Velero)


def backup_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    bsls = _crs(snap, "BackupStorageLocation", group="velero.io")
    for b in bsls:
        if str(b.status.get("phase") or "") == "Unavailable":
            out.append(
                _finding(
                    _ref(b),
                    "bsl",
                    f"Velero backup location {b.name} is unavailable",
                    Severity.HIGH,
                    "Velero cannot reach the object storage: backups fail and restores are impossible.",
                    evidence=[Evidence(source="velero", detail=clean(str(b.status.get("message") or ""), 260))],
                )
            )
    backups = _crs(snap, "Backup", group="velero.io")
    schedules = _crs(snap, "Schedule", group="velero.io")
    for sch in schedules:
        mine = [b for b in backups if b.labels.get("velero.io/schedule-name") == sch.name]
        latest = max(
            mine, key=lambda b: ts(b.status.get("startTimestamp")) or snap.now - timedelta(days=3650), default=None
        )
        if latest is not None and str(latest.status.get("phase")) in ("Failed", "PartiallyFailed", "FailedValidation"):
            phase = str(latest.status.get("phase"))
            out.append(
                _finding(
                    _ref(sch),
                    "last",
                    f"Velero schedule {sch.name}: last backup {phase}",
                    Severity.HIGH if phase != "PartiallyFailed" else Severity.MEDIUM,
                    f"Backup {latest.name} did not complete cleanly; the newest restorable point is older "
                    "than you think.",
                    evidence=[
                        Evidence(
                            source="velero", detail=f"{latest.name}: {phase}, errors={latest.status.get('errors', 0)}"
                        )
                    ],
                )
            )
        last = ts(sch.status.get("lastBackup"))
        if last is not None and snap.now - last > timedelta(days=7) and not sch.spec.get("paused"):
            out.append(
                _finding(
                    _ref(sch),
                    "stale",
                    f"Velero schedule {sch.name}: no backup for {(snap.now - last).days} days",
                    Severity.MEDIUM,
                    "The schedule has not produced a backup recently (paused controller, failing location "
                    "or cron typo).",
                    category="config",
                )
            )
    if (bsls or backups) and not schedules:
        out.append(
            _finding(
                WorkloadRef(kind="Velero", namespace="velero", name="velero"),
                "noschedule",
                "Velero is installed but no backup schedule exists",
                Severity.LOW,
                "Only manual backups will be taken.",
                category="config",
            )
        )
    return out


# ---------------------------------------------------------------- monitoring


def monitoring_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    for cr in _crs(snap, "Prometheus", "Alertmanager", group="monitoring.coreos.com"):
        avail = _cond(cr.conditions, "Available")
        if avail and avail.status == "False":
            what = (
                "metrics are not collected and alerts do not fire"
                if cr.kind == "Prometheus"
                else "alerts are not routed to anyone"
            )
            out.append(
                _finding(
                    _ref(cr),
                    "available",
                    f"{cr.kind} {cr.namespace}/{cr.name} is not available",
                    Severity.HIGH,
                    f"The Prometheus operator reports it unavailable: {what}.",
                    evidence=[_cev(avail)],
                )
            )
    return out


_ALERT_SEV = {"critical": Severity.HIGH, "error": Severity.HIGH, "warning": Severity.MEDIUM}
_IGNORE_ALERTS = {"Watchdog", "InfoInhibitor"}


def alert_findings(snap: Snapshot) -> list[Finding]:
    """Firing Prometheus alerts (from Alertmanager's webhook) attached to the workload they are about."""
    out: list[Finding] = []
    for a in snap.alerts:
        if a.status != "firing" or a.name in _IGNORE_ALERTS:
            continue
        ns = a.namespace or ""
        ref = WorkloadRef(kind="Namespace" if ns else "Cluster", namespace=ns, name=ns or "cluster")
        for key, kind in (
            ("deployment", "Deployment"),
            ("statefulset", "StatefulSet"),
            ("daemonset", "DaemonSet"),
            ("job_name", "Job"),
            ("cronjob", "CronJob"),
        ):
            if a.labels.get(key):
                ref = WorkloadRef(kind=kind, namespace=ns, name=a.labels[key])
                break
        else:
            if a.labels.get("pod"):
                ref = _owner(snap, "Pod", ns, a.labels["pod"])
        out.append(
            _finding(
                ref,
                f"alert-{a.fingerprint or a.name}",
                f"Alert firing: {a.name}",
                _ALERT_SEV.get(a.severity, Severity.LOW),
                clean(a.summary, 400) or "Prometheus alert reported by Alertmanager.",
                evidence=[
                    Evidence(
                        source="prometheus",
                        detail=f"severity={a.severity} since {a.starts_at.isoformat() if a.starts_at else '?'}",
                    )
                ],
            )
        )
    return out


# ---------------------------------------------------------------- nodes, load balancers, mesh


def _minor(v: str | None) -> tuple[int, int] | None:
    m = re.match(r"v?(\d+)\.(\d+)", v or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def cluster_findings(snap: Snapshot) -> list[Finding]:
    out: list[Finding] = []
    server = _minor(snap.server_version)
    versions = {n.name: _minor(n.kubelet_version) for n in snap.nodes if n.kubelet_version}
    if server:
        for name, kv in versions.items():
            if kv is None:
                continue
            if kv > server:
                out.append(
                    _finding(
                        WorkloadRef(kind="Node", namespace="", name=name),
                        "skew-new",
                        f"Node {name}: kubelet is newer than the API server",
                        Severity.HIGH,
                        "kubelets must not be newer than kube-apiserver (version skew policy). Upgrade the "
                        "control plane first.",
                        category="config",
                        evidence=[
                            Evidence(
                                source="node", detail=f"kubelet {kv[0]}.{kv[1]}, apiserver {server[0]}.{server[1]}"
                            )
                        ],
                    )
                )
            elif kv[0] == server[0] and server[1] - kv[1] > 3:
                out.append(
                    _finding(
                        WorkloadRef(kind="Node", namespace="", name=name),
                        "skew-old",
                        f"Node {name}: kubelet is more than 3 minor versions behind",
                        Severity.HIGH,
                        "Unsupported skew: kubelet may be at most 3 minor versions older than the API "
                        "server. Upgrade the node.",
                        category="config",
                        evidence=[
                            Evidence(
                                source="node", detail=f"kubelet {kv[0]}.{kv[1]}, apiserver {server[0]}.{server[1]}"
                            )
                        ],
                    )
                )
    for svc in snap.services:
        if svc.type == "LoadBalancer" and svc.lb_assigned is False:
            evs = [
                e
                for e in snap.events
                if e.namespace == svc.namespace and e.involved_name == svc.name and e.type == "Warning"
            ]
            out.append(
                _finding(
                    WorkloadRef(kind="Service", namespace=svc.namespace, name=svc.name),
                    "lb-pending",
                    f"LoadBalancer Service {svc.namespace}/{svc.name} has no external address",
                    Severity.HIGH,
                    "No load balancer was provisioned, so it is unreachable from outside. The LB "
                    "controller (cloud controller, AWS Load Balancer Controller, MetalLB, k3s ServiceLB) "
                    "is missing, failing, or out of addresses/quota.",
                    evidence=[Evidence(source="event", detail=f"{e.reason}: {clean(e.message, 200)}") for e in evs[:2]],
                )
            )
    injected = {
        n.name: n.labels
        for n in snap.namespaces
        if n.labels.get("istio-injection") == "enabled" or n.labels.get("istio.io/rev")
    }
    for p in snap.pods:
        if p.phase != "Running":
            continue
        names = {c.name for c in p.containers}
        if (
            p.namespace in injected
            and "istio-proxy" not in names
            and p.labels.get("sidecar.istio.io/inject") != "false"
            and not p.host_network
        ):
            out.append(
                _finding(
                    p.workload,
                    f"mesh-missing-{p.workload.name}",
                    f"{p.workload.name} runs without the Istio sidecar in a meshed namespace",
                    Severity.MEDIUM,
                    "Its pods started before injection was enabled (or injection failed), so they are "
                    "outside the mesh: no mTLS, and peers with PeerAuthentication STRICT reject them. "
                    "Restart the workload.",
                    category="config",
                )
            )
        for c in p.containers:
            if c.name in ("istio-proxy", "linkerd-proxy") and not c.ready:
                out.append(
                    _finding(
                        p.workload,
                        f"sidecar-{p.workload.name}",
                        f"{p.workload.name}: {c.name} sidecar is not ready",
                        Severity.HIGH,
                        "The mesh proxy is not ready, so traffic to and from the pod fails even if the app "
                        "is healthy (control plane unreachable, certificate or config error).",
                        evidence=[
                            Evidence(
                                source="pod-status", detail=f"{p.name}/{c.name}: {c.state.reason or c.state.state}"
                            )
                        ],
                    )
                )
    return _dedupe(out)


def _dedupe(items: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in items:
        seen.setdefault(f.id, f)
    return list(seen.values())


def netpol_covers(snap: Snapshot, p: Pod) -> bool:
    return bool(selectors.covering_policies(p, snap.network_policies, "Ingress"))


def all_findings(snap: Snapshot) -> list[Finding]:
    return _dedupe(
        gateway_findings(snap)
        + gitops_findings(snap)
        + secret_findings(snap)
        + autoscaling_findings(snap)
        + storage_findings(snap)
        + policy_findings(snap)
        + backup_findings(snap)
        + monitoring_findings(snap)
        + alert_findings(snap)
        + cluster_findings(snap)
    )
