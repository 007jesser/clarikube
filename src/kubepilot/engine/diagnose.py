"""Reliability diagnosis: why is a workload unhealthy, and what changed?

Every rule is deterministic and produces a ``Finding`` with evidence and remediation hints.
The rollout correlator links failures to the most recent template change of the controller.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from datetime import timedelta

from kubepilot import quantity
from kubepilot.models import (
    Container,
    Event,
    Evidence,
    Finding,
    Pod,
    RemediationHint,
    ReplicaSetInfo,
    Severity,
    WorkloadRef,
)
from kubepilot.sanitize import clean
from kubepilot.source.base import Snapshot

ROLLOUT_CORRELATION_WINDOW = timedelta(hours=6)
HIGH_RESTARTS = 5

EXIT_CODES = {
    0: "exited normally (completed) — check restartPolicy / command",
    1: "generic application error — check the application logs",
    2: "misuse of shell builtin / bad arguments",
    126: "command not executable (permissions)",
    127: "command not found (wrong entrypoint/command or missing binary)",
    128 + 9: "killed by SIGKILL (often OOM or liveness probe kill)",
    128 + 11: "segmentation fault",
    128 + 15: "terminated by SIGTERM (graceful shutdown, e.g. liveness/eviction)",
}


def _fid(wl: WorkloadRef, code: str, extra: str = "") -> str:
    return hashlib.sha1(f"{wl.key}|{code}|{extra}".encode(), usedforsecurity=False).hexdigest()[:10]


# ---------------------------------------------------------------- rollout diff


def template_diff(old: ReplicaSetInfo, new: ReplicaSetInfo) -> list[str]:
    """Human-readable differences between two pod templates (images and resources)."""
    changes: list[str] = []
    old_c = {c.name: c for c in old.containers if not c.init}
    for c in new.containers:
        if c.init:
            continue
        o = old_c.get(c.name)
        if o is None:
            changes.append(f"container {c.name} added")
            continue
        if o.image != c.image:
            changes.append(f"{c.name}: image {o.image} → {c.image}")
        for field in ("cpu_request", "cpu_limit", "memory_request", "memory_limit"):
            a, b = getattr(o.resources, field), getattr(c.resources, field)
            if a != b:
                changes.append(f"{c.name}: {field.replace('_', ' ')} {a or 'unset'} → {b or 'unset'}")
    return changes


def latest_rollout(snap: Snapshot, wl: WorkloadRef) -> tuple[ReplicaSetInfo, ReplicaSetInfo | None] | None:
    rss = [r for r in snap.replicasets_of(wl) if r.revision is not None]
    if not rss:
        return None
    rss.sort(key=lambda r: r.revision or 0)
    current = rss[-1]
    previous = rss[-2] if len(rss) > 1 else None
    return current, previous


# ---------------------------------------------------------------- helpers


def _events(snap: Snapshot, wl: WorkloadRef, reasons: Iterable[str]) -> list[Event]:
    rs = set(reasons)
    return [e for e in snap.events_for(wl) if e.reason in rs]


def _ev(e: Event) -> Evidence:
    return Evidence(
        source="event",
        detail=f"{e.reason} on {e.involved_kind}/{e.involved_name} (x{e.count}): {clean(e.message, 240)}",
        at=e.last_seen,
    )


def _container_iter(pods: list[Pod]) -> Iterable[tuple[Pod, Container]]:
    for p in pods:
        for c in p.app_containers:
            yield p, c


# ---------------------------------------------------------------- rules


def _rule_oom(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    hits: dict[str, list[tuple[Pod, Container]]] = {}
    for p, c in _container_iter(pods):
        if "OOMKilled" in (c.last_state.reason, c.state.reason):
            hits.setdefault(c.name, []).append((p, c))
    out = []
    for cname, items in hits.items():
        c = items[0][1]
        restarts = sum(x[1].restart_count for x in items)
        limit = c.resources.memory_limit
        evidence = [
            Evidence(
                source="pod-status",
                detail=f"{p.name}/{cname}: last terminated OOMKilled (exit 137), restarts={cc.restart_count}",
                at=cc.last_state.finished_at or cc.state.finished_at,
            )
            for p, cc in items
        ]
        explanation = (
            f"Container '{cname}' is being killed by the kernel OOM killer: it exceeds its memory limit "
            f"({limit or 'no limit — node memory pressure'}). {len(items)} pod(s) affected, {restarts} restarts total."
        )
        hints: list[RemediationHint] = []
        proposed: str | None = None
        prev_limit = rollout.previous_value(cname, "memory_limit")
        if rollout.changed and prev_limit and limit and quantity.parse(prev_limit) > quantity.parse(limit):
            proposed = prev_limit
            explanation += (
                f" The latest rollout (revision {rollout.current_rev}) lowered the memory limit from "
                f"{prev_limit} to {limit} — this is the most likely cause."
            )
        elif limit:
            proposed = quantity.format_memory(quantity.parse(limit) * 2)
        if limit and proposed:
            hints.append(
                RemediationHint(
                    kind="set-memory-limit",
                    params={"container": cname, "current": limit, "proposed": proposed},
                    summary=f"Set memory limit of '{cname}' to {proposed} (currently {limit})",
                )
            )
        if rollout.changed and rollout.previous is not None:
            hints.append(rollout.rollback_hint())
        evidence.extend(rollout.evidence())
        out.append(
            Finding(
                id=_fid(wl, "oom", cname),
                workload=wl,
                category="reliability",
                title=f"OOMKilled: '{cname}' exceeds its memory limit",
                severity=Severity.HIGH,
                explanation=explanation,
                evidence=evidence,
                remediations=hints,
            )
        )
    return out


def _rule_crashloop(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    items = [
        (p, c)
        for p, c in _container_iter(pods)
        if c.state.reason == "CrashLoopBackOff" and c.last_state.reason != "OOMKilled"
    ]
    if not items:
        return []
    p, c = items[0]
    code = c.last_state.exit_code
    meaning = EXIT_CODES.get(code, "non-zero exit — check the application logs") if code is not None else "unknown"
    evidence = [
        Evidence(
            source="pod-status",
            detail=f"{pp.name}/{cc.name}: CrashLoopBackOff, last exit code {cc.last_state.exit_code} "
            f"({clean(cc.last_state.reason, 60)}), restarts={cc.restart_count}",
            at=cc.last_state.finished_at,
        )
        for pp, cc in items
    ]
    evidence += [_ev(e) for e in _events(snap, wl, ["BackOff"])][:3]
    evidence += rollout.evidence()
    hints = [rollout.rollback_hint()] if rollout.changed and rollout.previous else []
    hints.append(
        RemediationHint(
            kind="inspect-logs",
            params={"namespace": p.namespace, "pod": p.name, "container": c.name},
            summary=f"Check previous logs: kubectl logs -n {p.namespace} {p.name} -c {c.name} --previous",
        )
    )
    return [
        Finding(
            id=_fid(wl, "crashloop", c.name),
            workload=wl,
            category="reliability",
            title=f"CrashLoopBackOff: '{c.name}' keeps exiting (code {code})",
            severity=Severity.HIGH,
            explanation=f"Container '{c.name}' starts and exits repeatedly. Exit code {code}: {meaning}."
            + (f" Started after rollout revision {rollout.current_rev}." if rollout.changed else ""),
            evidence=evidence,
            remediations=hints,
        )
    ]


_PULL_REASONS = {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "ErrImageNeverPull"}


def _rule_image_pull(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    items = [(p, c) for p, c in _container_iter(pods) if c.state.reason in _PULL_REASONS]
    if not items:
        return []
    _, c = items[0]
    events = [e for e in _events(snap, wl, ["Failed"]) if "pull" in e.message.lower()]
    msg = " ".join(e.message.lower() for e in events) + " " + (c.state.message or "").lower()
    if "not found" in msg or "manifest unknown" in msg:
        cause = "the image tag does not exist in the registry (typo or not pushed yet)"
    elif "unauthorized" in msg or "denied" in msg or "authentication" in msg:
        cause = "the registry rejected the credentials (missing/expired imagePullSecret)"
    elif "timeout" in msg or "i/o timeout" in msg or "no such host" in msg:
        cause = "the node cannot reach the registry (network/DNS/egress)"
    else:
        cause = "the image could not be pulled (see events)"
    hints: list[RemediationHint] = []
    prev_image = rollout.previous_image(c.name)
    if prev_image and prev_image != c.image:
        hints.append(
            RemediationHint(
                kind="set-image",
                params={"container": c.name, "current": c.image, "proposed": prev_image},
                summary=f"Revert '{c.name}' image to last working {prev_image}",
            )
        )
    evidence = [
        Evidence(
            source="pod-status",
            detail=f"{p.name}/{cc.name}: {cc.state.reason} for image {clean(cc.image, 200)}",
        )
        for p, cc in items
    ]
    evidence += [_ev(e) for e in events][:2] + rollout.evidence()
    return [
        Finding(
            id=_fid(wl, "imagepull", c.name),
            workload=wl,
            category="reliability",
            title=f"Image pull failing for '{c.name}'",
            severity=Severity.HIGH,
            explanation=f"Pods cannot start because {cause}. Image: {clean(c.image, 200)}.",
            evidence=evidence,
            remediations=hints,
        )
    ]


_MISSING_REF = re.compile(r'(secret|configmap)s? "([^"]+)" not found', re.IGNORECASE)


def _rule_config_error(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    items = [
        (p, c)
        for p, c in _container_iter(pods)
        if c.state.reason in ("CreateContainerConfigError", "CreateContainerError", "RunContainerError")
    ]
    if not items:
        return []
    p, c = items[0]
    m = _MISSING_REF.search(c.state.message or "")
    if m:
        kind, name = m.group(1).lower(), m.group(2)
        expl = (
            f"Container '{c.name}' references {kind} '{name}' which does not exist in namespace "
            f"'{p.namespace}'. Create it (e.g. via your secrets manager / External Secrets) or fix the reference."
        )
        hints = [
            RemediationHint(
                kind="create-missing-reference",
                params={"kind": kind, "name": name, "namespace": p.namespace},
                summary=f"Provide {kind} '{name}' in namespace '{p.namespace}' (kubepilot never creates secrets)",
            )
        ]
    else:
        expl = f"Container '{c.name}' cannot be created: {clean(c.state.message, 240)}"
        hints = []
    return [
        Finding(
            id=_fid(wl, "configerror", c.name),
            workload=wl,
            category="config",
            title=f"{c.state.reason}: '{c.name}' cannot start",
            severity=Severity.HIGH,
            explanation=expl,
            evidence=[Evidence(source="pod-status", detail=f"{p.name}/{c.name}: {clean(c.state.message, 240)}")]
            + [_ev(e) for e in _events(snap, wl, ["Failed"])][:2],
            remediations=hints,
        )
    ]


def _rule_unschedulable(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    pending = [p for p in pods if p.phase == "Pending" and p.unschedulable_message]
    if not pending:
        return []
    p = pending[0]
    msg = p.unschedulable_message or ""
    reasons = []
    hints: list[RemediationHint] = []
    if "Insufficient memory" in msg:
        reasons.append("not enough allocatable memory on any eligible node")
        largest = max(
            (quantity.parse(n.allocatable_memory) for n in snap.nodes if n.allocatable_memory and not n.taints),
            default=None,
        )
        for c in p.app_containers:
            req = c.resources.memory_request
            if req and largest is not None and quantity.parse(req) > largest:
                step = 256 * 2**20  # round down to 256Mi steps
                proposed = quantity.format_memory((largest * 3 / 4) // step * step)
                reasons.append(
                    f"'{c.name}' requests {req} but the largest schedulable node only has "
                    f"{quantity.format_memory(largest)} allocatable — it can never fit"
                )
                hints.append(
                    RemediationHint(
                        kind="set-memory-request",
                        params={"container": c.name, "current": req, "proposed": proposed},
                        summary=f"Lower memory request of '{c.name}' to {proposed} or add a bigger node pool",
                    )
                )
    if "Insufficient cpu" in msg:
        reasons.append("not enough allocatable CPU on any eligible node")
    if "untolerated taint" in msg:
        reasons.append("some nodes are tainted and the pod has no matching toleration")
    if "didn't match Pod's node affinity" in msg or "node selector" in msg.lower():
        reasons.append("nodeSelector/affinity excludes the available nodes")
    if "persistentvolumeclaim" in msg.lower() or "unbound" in msg.lower():
        reasons.append("a PersistentVolumeClaim is not bound")
    return [
        Finding(
            id=_fid(wl, "unschedulable"),
            workload=wl,
            category="reliability",
            title="Pods stuck Pending: unschedulable",
            severity=Severity.HIGH,
            explanation="The scheduler cannot place the pod: " + ("; ".join(reasons) or clean(msg, 240)) + ".",
            evidence=[Evidence(source="pod-status", detail=f"{p.name}: {clean(msg, 300)}")]
            + [_ev(e) for e in _events(snap, wl, ["FailedScheduling"])][:1],
            remediations=hints,
        )
    ]


def _rule_probes(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    unhealthy = _events(snap, wl, ["Unhealthy"])
    readiness = [e for e in unhealthy if "readiness probe" in e.message.lower()]
    liveness = [e for e in unhealthy if "liveness probe" in e.message.lower()]
    out = []
    if liveness:
        out.append(
            Finding(
                id=_fid(wl, "liveness"),
                workload=wl,
                category="reliability",
                title="Liveness probe failures are restarting containers",
                severity=Severity.HIGH,
                explanation="The kubelet kills containers whose liveness probe fails. Check whether the probe is "
                "too aggressive (initialDelaySeconds/timeoutSeconds) or the app is genuinely hanging.",
                evidence=[_ev(e) for e in liveness][:3],
            )
        )
    if readiness:
        out.append(
            Finding(
                id=_fid(wl, "readiness"),
                workload=wl,
                category="reliability",
                title="Readiness probe failing: pods removed from Service endpoints",
                severity=Severity.MEDIUM,
                explanation="Pods are running but not Ready, so they receive no traffic. Usually a dependency "
                "(DB, downstream API) is unavailable or the probe path/port is wrong.",
                evidence=[_ev(e) for e in readiness][:3],
            )
        )
    return out


def _rule_restarts(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    noisy = [
        (p, c)
        for p, c in _container_iter(pods)
        if c.restart_count >= HIGH_RESTARTS
        and c.state.state == "running"
        and c.state.reason is None
        and c.last_state.reason not in ("OOMKilled",)
    ]
    if not noisy:
        return []
    _, c = noisy[0]
    return [
        Finding(
            id=_fid(wl, "restarts", c.name),
            workload=wl,
            category="reliability",
            title=f"High restart count for '{c.name}' ({c.restart_count})",
            severity=Severity.MEDIUM,
            explanation=f"Currently running but restarted {c.restart_count} times; last termination: "
            f"{clean(c.last_state.reason, 60) or 'unknown'} (exit {c.last_state.exit_code}).",
            evidence=[
                Evidence(source="pod-status", detail=f"{pp.name}/{cc.name}: restarts={cc.restart_count}")
                for pp, cc in noisy
            ],
        )
    ]


def _rule_node(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    nodes = {n.name: n for n in snap.nodes}
    bad = []
    for p in pods:
        n = nodes.get(p.node or "")
        if n is None:
            continue
        pressure = [k for k in ("MemoryPressure", "DiskPressure", "PIDPressure") if n.conditions.get(k) == "True"]
        if not n.ready or pressure:
            bad.append((p, n, pressure))
    if not bad:
        return []
    return [
        Finding(
            id=_fid(wl, "node"),
            workload=wl,
            category="reliability",
            title="Pods run on unhealthy node(s)",
            severity=Severity.HIGH,
            explanation="Node problems (NotReady or resource pressure) can cause evictions and failures "
            "unrelated to the application itself.",
            evidence=[
                Evidence(
                    source="node",
                    detail=f"{p.name} on {n.name}: ready={n.ready} pressure={','.join(pr) or 'none'}",
                )
                for p, n, pr in bad
            ],
        )
    ]


def _rule_config_hygiene(snap: Snapshot, wl: WorkloadRef, pods: list[Pod], rollout: Rollout) -> list[Finding]:
    if not pods:
        return []
    p = pods[0]
    issues = []
    for c in p.app_containers:
        if not c.resources.memory_limit:
            issues.append(f"'{c.name}' has no memory limit")
        if not c.resources.cpu_request or not c.resources.memory_request:
            issues.append(f"'{c.name}' is missing CPU/memory requests")
        if not c.has_readiness_probe and wl.kind in ("Deployment", "StatefulSet"):
            issues.append(f"'{c.name}' has no readiness probe")
        if c.image.endswith(":latest") or ":" not in c.image.rsplit("/", 1)[-1]:
            issues.append(f"'{c.name}' uses a mutable/untagged image ({clean(c.image, 120)})")
    if not issues:
        return []
    return [
        Finding(
            id=_fid(wl, "hygiene"),
            workload=wl,
            category="config",
            title="Configuration best-practice gaps",
            severity=Severity.LOW,
            explanation="; ".join(issues) + ".",
            evidence=[Evidence(source="pod-spec", detail=i) for i in issues],
        )
    ]


# ---------------------------------------------------------------- rollout context


class Rollout:
    """Context about the latest template change of a workload, used by several rules."""

    def __init__(self, snap: Snapshot, wl: WorkloadRef, pods: list[Pod]) -> None:
        self.current: ReplicaSetInfo | None = None
        self.previous: ReplicaSetInfo | None = None
        self.changes: list[str] = []
        self.changed = False
        lr = latest_rollout(snap, wl)
        if lr:
            self.current, self.previous = lr
        if self.current and self.previous and self.current.created_at:
            self.changes = template_diff(self.previous, self.current)
            recent = snap.now - self.current.created_at <= ROLLOUT_CORRELATION_WINDOW
            self.changed = recent and bool(self.changes)

    @property
    def current_rev(self) -> int | None:
        return self.current.revision if self.current else None

    def _prev_container(self, name: str) -> Container | None:
        if not self.previous:
            return None
        return next((c for c in self.previous.containers if c.name == name), None)

    def previous_value(self, container: str, field: str) -> str | None:
        c = self._prev_container(container)
        return getattr(c.resources, field) if c else None

    def previous_image(self, container: str) -> str | None:
        c = self._prev_container(container)
        return c.image if c else None

    def evidence(self) -> list[Evidence]:
        if not self.changed or not self.current:
            return []
        return [
            Evidence(
                source="rollout",
                detail=f"revision {self.current.revision} ({self.current.name}) rolled out; changes: "
                + "; ".join(self.changes),
                at=self.current.created_at,
            )
        ]

    def rollback_hint(self) -> RemediationHint:
        assert self.previous is not None
        return RemediationHint(
            kind="rollback-template",
            params={"to_revision": str(self.previous.revision), "replicaset": self.previous.name},
            summary=f"Revert the template changes of revision {self.current_rev} "
            f"(back to revision {self.previous.revision}) in Git",
        )


RULES = [
    _rule_oom,
    _rule_crashloop,
    _rule_image_pull,
    _rule_config_error,
    _rule_unschedulable,
    _rule_probes,
    _rule_restarts,
    _rule_node,
]


def diagnose_workload(snap: Snapshot, wl: WorkloadRef, include_hygiene: bool = False) -> list[Finding]:
    pods = snap.pods_of(wl)
    rollout = Rollout(snap, wl, pods)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(snap, wl, pods, rollout))
    if include_hygiene:
        findings.extend(_rule_config_hygiene(snap, wl, pods, rollout))
    return sorted(findings, key=lambda f: -f.severity)


def diagnose_all(
    snap: Snapshot, include_hygiene: bool = False, min_severity: Severity = Severity.MEDIUM
) -> list[Finding]:
    out: list[Finding] = []
    for wl in snap.workloads():
        out.extend(f for f in diagnose_workload(snap, wl, include_hygiene) if f.severity >= min_severity)
    return sorted(out, key=lambda f: (-f.severity, f.workload.key))
