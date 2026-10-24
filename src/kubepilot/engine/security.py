"""Security triage: correlate runtime (Falco), image (Trivy) and exposure (spec, RBAC,
NetworkPolicy) signals per workload into a ranked list of incidents.

Scoring is explicit and documented in ``SCORING`` so results are explainable and auditable.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from kubepilot.engine import rbac, selectors
from kubepilot.engine.allowlist import Allowlist
from kubepilot.models import (
    Evidence,
    FalcoAlert,
    Pod,
    RemediationHint,
    SecurityIncident,
    Severity,
    Vulnerability,
    WorkloadRef,
)
from kubepilot.sanitize import clean
from kubepilot.source.base import Snapshot

SCORING: dict[str, int] = {
    # runtime (Falco) — highest single alert counts fully, extra distinct rules add a bonus
    "falco.critical": 40,
    "falco.high": 30,
    "falco.medium": 20,
    "falco.low": 10,
    "falco.extra_rule": 5,
    "falco.extra_rule_cap": 15,
    # image (Trivy)
    "cve.critical": 25,
    "cve.high": 10,
    # workload exposure
    "privileged": 20,
    "host_namespace": 15,
    "host_path": 15,
    "dangerous_caps": 10,
    "runs_as_root": 10,
    "priv_escalation": 5,
    "no_ingress_netpol": 10,
    "external_service": 15,
    # RBAC points come from engine.rbac.RiskyPermission.points (capped)
    "rbac_cap": 30,
}
CORRELATION_MULTIPLIER = 1.5
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "ALL"}
_FALCO_POINTS = {
    Severity.CRITICAL: SCORING["falco.critical"],
    Severity.HIGH: SCORING["falco.high"],
    Severity.MEDIUM: SCORING["falco.medium"],
    Severity.LOW: SCORING["falco.low"],
    Severity.INFO: 0,
}


def severity_for(score: int) -> Severity:
    if score >= 70:
        return Severity.CRITICAL
    if score >= 45:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    if score >= 10:
        return Severity.LOW
    return Severity.INFO


@dataclass
class _Acc:
    wl: WorkloadRef
    points: dict[str, int] = field(default_factory=dict)
    signals: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    hints: dict[str, RemediationHint] = field(default_factory=dict)
    suppressed: int = 0
    runtime: bool = False
    exploitable: bool = False
    overexposed: bool = False

    def add(self, key: str, pts: int, signal: str) -> None:
        if pts <= 0:
            return
        self.points[key] = max(self.points.get(key, 0), pts)
        self.signals.append(f"{signal} (+{pts})")

    def hint(self, h: RemediationHint) -> None:
        self.hints.setdefault(h.kind, h)


def _alerts_by_workload(snap: Snapshot) -> dict[WorkloadRef, list[FalcoAlert]]:
    pod_index = {(p.namespace, p.name): p.workload for p in snap.pods}
    out: dict[WorkloadRef, list[FalcoAlert]] = defaultdict(list)
    for a in snap.falco_alerts:
        if a.namespace and a.pod:
            wl = pod_index.get((a.namespace, a.pod)) or WorkloadRef(kind="Pod", namespace=a.namespace, name=a.pod)
            out[wl].append(a)
    return out


def _score_runtime(acc: _Acc, alerts: list[FalcoAlert], allow: Allowlist) -> None:
    active = []
    for a in alerts:
        if allow.suppresses(a):
            acc.suppressed += 1
        else:
            active.append(a)
    if not active:
        return
    acc.runtime = any(a.severity >= Severity.MEDIUM for a in active)
    top = max(active, key=lambda a: a.severity)
    acc.add("falco", _FALCO_POINTS[top.severity], f"Falco {top.priority}: {top.rule}")
    rules = {a.rule for a in active}
    extra = min((len(rules) - 1) * SCORING["falco.extra_rule"], SCORING["falco.extra_rule_cap"])
    if extra:
        acc.add("falco_extra", extra, f"{len(rules)} distinct Falco rules fired")
    for a in sorted(active, key=lambda a: a.time)[:8]:
        acc.evidence.append(
            Evidence(source="falco", detail=f"[{a.priority}] {a.rule}: {clean(a.output, 300)}", at=a.time)
        )
    if top.severity >= Severity.HIGH:
        acc.hint(
            RemediationHint(
                kind="isolate-workload",
                params={},
                summary="Contain now: apply a deny-all NetworkPolicy to this workload, then investigate",
            )
        )
        acc.hint(
            RemediationHint(
                kind="rotate-credentials",
                params={},
                summary="Assume credentials reachable from the pod are compromised: rotate the SA token "
                "and any mounted secrets after containment",
            )
        )


def _score_vulns(acc: _Acc, snap: Snapshot) -> None:
    reports = [r for r in snap.vulnerability_reports if r.workload == acc.wl]
    vulns: list[tuple[str, Vulnerability]] = [(r.container, v) for r in reports for v in r.vulnerabilities]
    crit = [x for x in vulns if x[1].severity == Severity.CRITICAL]
    high = [x for x in vulns if x[1].severity == Severity.HIGH]
    if crit:
        acc.exploitable = True
        acc.add("cve", SCORING["cve.critical"], f"{len(crit)} critical CVE(s) in running image")
    elif high:
        acc.add("cve", SCORING["cve.high"], f"{len(high)} high CVE(s) in running image")
    fixable = [(c, v) for c, v in crit + high if v.fixed_version]
    for c, v in (crit + high)[:5]:
        fix = f", fixed in {v.fixed_version}" if v.fixed_version else ", no fix yet"
        acc.evidence.append(
            Evidence(
                source="trivy",
                detail=f"{v.id} [{v.severity.label}] {clean(v.package, 80)} {clean(v.installed_version, 40)}{fix}"
                f" (container {c}): {clean(v.title, 160)}",
            )
        )
    if fixable:
        upgrades = ", ".join(sorted({f"{v.package}>={v.fixed_version}" for _, v in fixable}))
        acc.hint(
            RemediationHint(
                kind="rebuild-image",
                params={"upgrades": upgrades},
                summary=f"Rebuild the image with: {upgrades}",
            )
        )


def _score_exposure(acc: _Acc, pods: list[Pod], snap: Snapshot) -> None:
    if not pods:
        return
    p = pods[0]  # pods of one workload share a template
    harden_needed = False
    for c in p.app_containers:
        sc = c.security
        if sc.privileged:
            acc.add("privileged", SCORING["privileged"], f"container '{c.name}' is privileged")
            acc.overexposed = harden_needed = True
        caps = {x.upper().removeprefix("CAP_") for x in sc.capabilities_add} & DANGEROUS_CAPS
        if caps:
            acc.add("caps", SCORING["dangerous_caps"], f"'{c.name}' adds capabilities {sorted(caps)}")
            acc.overexposed = harden_needed = True
        if sc.may_run_as_root:
            acc.add("root", SCORING["runs_as_root"], f"'{c.name}' may run as root (no runAsNonRoot/runAsUser)")
            harden_needed = True
        if sc.allow_privilege_escalation is not False and not sc.privileged:
            acc.add("escalation", SCORING["priv_escalation"], f"'{c.name}' allows privilege escalation")
            harden_needed = True
    host_ns = [n for n, on in (("hostNetwork", p.host_network), ("hostPID", p.host_pid), ("hostIPC", p.host_ipc)) if on]
    if host_ns:
        acc.add("host_ns", SCORING["host_namespace"], f"uses host namespaces: {', '.join(host_ns)}")
        acc.overexposed = True
    host_paths = [v.source or v.name for v in p.volumes if v.kind == "hostPath"]
    if host_paths:
        acc.add("host_path", SCORING["host_path"], f"mounts hostPath {', '.join(host_paths)}")
        acc.overexposed = True
    if harden_needed:
        acc.hint(
            RemediationHint(
                kind="harden-security-context",
                params={},
                summary="Run as non-root, disallow privilege escalation, drop ALL capabilities, read-only root FS",
            )
        )
    if not selectors.covering_policies(p, snap.network_policies, "Ingress"):
        acc.add("netpol", SCORING["no_ingress_netpol"], "no NetworkPolicy restricts ingress")
        acc.overexposed = True
        acc.hint(
            RemediationHint(
                kind="restrict-ingress",
                params={},
                summary="Add a NetworkPolicy allowing only the expected callers",
            )
        )

    external = sorted(
        f"{svc.name} ({svc.type})"
        for svc in snap.services
        if svc.external
        and svc.namespace == p.namespace
        and svc.selector
        and all(p.labels.get(k) == v for k, v in svc.selector.items())
    )
    if external:
        acc.add(
            "external", SCORING["external_service"], f"reachable from outside the cluster via {', '.join(external)}"
        )
        acc.overexposed = True

    if p.automount_sa_token:
        grants = rbac.grants_for(p.namespace, p.service_account, snap.roles, snap.bindings)
        risky = rbac.risky_permissions(grants)
        if risky:
            pts = min(sum(r.points for r in risky), SCORING["rbac_cap"])
            acc.add(
                "rbac",
                pts,
                f"ServiceAccount '{p.service_account}': " + "; ".join(r.description for r in risky[:3]),
            )
            acc.overexposed = True
            for r in risky[:3]:
                acc.evidence.append(Evidence(source="rbac", detail=f"{r.description} via {r.via}"))
            acc.hint(
                RemediationHint(
                    kind="reduce-rbac",
                    params={"service_account": p.service_account},
                    summary=f"Remove unneeded permissions from ServiceAccount '{p.service_account}' "
                    "or set automountServiceAccountToken: false",
                )
            )


def _summary(acc: _Acc, score: int) -> str:
    parts = []
    if acc.runtime:
        parts.append("active suspicious runtime behaviour")
    if acc.exploitable:
        parts.append("critical CVEs in the running image")
    if acc.overexposed:
        parts.append("excessive privileges/exposure")
    if not parts:
        parts.append("minor hardening gaps")
    verdict = "LIKELY COMPROMISE — contain first" if (acc.runtime and (acc.exploitable or acc.overexposed)) else ""
    s = f"{acc.wl.kind} {acc.wl.namespace}/{acc.wl.name}: " + ", ".join(parts)
    return f"{s}. {verdict}".strip() if verdict else s + "."


def triage(
    snap: Snapshot,
    allow: Allowlist | None = None,
    since: timedelta | None = None,
    min_score: int = 0,
) -> list[SecurityIncident]:
    """Rank workloads by correlated security risk."""
    allow = allow or Allowlist()
    alerts = _alerts_by_workload(snap)
    if since is not None:
        cutoff = snap.now - since
        alerts = {wl: [a for a in al if a.time >= cutoff] for wl, al in alerts.items()}
    workloads = {w.key: w for w in snap.workloads()}
    for wl in alerts:
        workloads.setdefault(wl.key, wl)

    incidents: list[SecurityIncident] = []
    for wl in workloads.values():
        pods = [p for p in snap.pods_of(wl) if p.phase not in ("Succeeded", "Failed")] or snap.pods_of(wl)
        acc = _Acc(wl=wl)
        _score_runtime(acc, alerts.get(wl, []), allow)
        _score_vulns(acc, snap)
        _score_exposure(acc, pods, snap)
        base = sum(acc.points.values())
        if acc.runtime and (acc.exploitable or acc.overexposed):
            score = round(base * CORRELATION_MULTIPLIER)
            acc.signals.append(f"correlated runtime + exposure signals (x{CORRELATION_MULTIPLIER})")
        else:
            score = base
        score = min(score, 100)
        if score < min_score:
            continue
        iid = hashlib.sha1(wl.key.encode(), usedforsecurity=False).hexdigest()[:10]
        incidents.append(
            SecurityIncident(
                id=iid,
                workload=wl,
                score=score,
                severity=severity_for(score),
                summary=_summary(acc, score),
                signals=acc.signals,
                evidence=acc.evidence,
                suppressed_alerts=acc.suppressed,
                remediations=list(acc.hints.values()),
            )
        )
    return sorted(incidents, key=lambda i: (-i.score, i.workload.key))
