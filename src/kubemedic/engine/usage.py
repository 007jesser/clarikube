"""Usage-based checks from metrics-server (metrics.k8s.io): OOM risk, CPU saturation, rightsizing.

metrics-server reports a recent average (default window ~15-30s), not a peak: findings say "currently" and
rightsizing keeps generous headroom. Nothing here runs when metrics-server is absent.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

from kubemedic import quantity
from kubemedic.models import Evidence, Finding, RemediationHint, Severity, WorkloadRef
from kubemedic.source.base import Snapshot

MIB = 2**20


def _fid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:10]


def _bytes(v: str | None) -> int | None:
    if not v:
        return None
    try:
        return int(quantity.parse(v))
    except (ValueError, ArithmeticError):
        return None


def _millis(v: str | None) -> int | None:
    if not v:
        return None
    try:
        return int(float(quantity.parse(v)) * 1000)
    except (ValueError, ArithmeticError):
        return None


def _fmt(b: float) -> str:
    return quantity.format_memory(int(b))


def _round_mem(b: float) -> int:
    step = 128 * MIB if b <= 2 * 2**30 else 512 * MIB
    return int(math.ceil(b / step) * step)


def usage_findings(snap: Snapshot) -> list[Finding]:
    if not snap.pod_metrics:
        return []
    by_pod = {(m.namespace, m.pod): m for m in snap.pod_metrics}
    out: dict[str, Finding] = {}
    over: dict[WorkloadRef, list[tuple[str, int, int]]] = {}
    for p in snap.pods:
        m = by_pod.get((p.namespace, p.name))
        if m is None or p.phase != "Running":
            continue
        for c in p.app_containers:
            u = m.containers.get(c.name)
            if u is None:
                continue
            lim = _bytes(c.resources.memory_limit)
            req = _bytes(c.resources.memory_request)
            if lim and u.memory_bytes >= 0.9 * lim:
                proposed = _round_mem(max(u.memory_bytes * 1.5, lim * 1.25))
                fid = _fid(p.workload.key, "oomrisk", c.name)
                out.setdefault(
                    fid,
                    Finding(
                        id=fid,
                        workload=p.workload,
                        category="reliability",
                        title=f"'{c.name}' is at {u.memory_bytes * 100 // lim}% of its memory limit (OOM risk)",
                        severity=Severity.HIGH,
                        explanation=f"Pod {p.name} currently uses {_fmt(u.memory_bytes)} of a {_fmt(lim)} limit. "
                        "One more "
                        "allocation spike and the kernel kills it (OOMKilled). Raise the limit or reduce memory use.",
                        evidence=[
                            Evidence(
                                source="metrics-server",
                                detail=f"{p.name}/{c.name}: {_fmt(u.memory_bytes)} used, limit {_fmt(lim)}",
                            )
                        ],
                        remediations=[
                            RemediationHint(
                                kind="set-memory-limit",
                                params={
                                    "container": c.name,
                                    "current": c.resources.memory_limit or "",
                                    "proposed": _fmt(proposed),
                                },
                                summary=f"Raise memory limit of '{c.name}' to {_fmt(proposed)}",
                            )
                        ],
                    ),
                )
            cpu_lim = _millis(c.resources.cpu_limit)
            if cpu_lim and u.cpu_millis >= 0.9 * cpu_lim:
                fid = _fid(p.workload.key, "cputhrottle", c.name)
                out.setdefault(
                    fid,
                    Finding(
                        id=fid,
                        workload=p.workload,
                        category="reliability",
                        title=f"'{c.name}' is using its whole CPU limit (throttled)",
                        severity=Severity.MEDIUM,
                        explanation=f"{u.cpu_millis}m used of a {cpu_lim}m limit: the container is CPU-throttled, "
                        "which "
                        "shows up as latency and probe timeouts. Raise or remove the CPU limit.",
                        evidence=[
                            Evidence(
                                source="metrics-server", detail=f"{p.name}/{c.name}: {u.cpu_millis}m of {cpu_lim}m"
                            )
                        ],
                    ),
                )
            if req and req >= 512 * MIB and u.memory_bytes * 4 < req:
                over.setdefault(p.workload, []).append((c.name, req, u.memory_bytes))
    for wl, items in over.items():
        name, req, used = max(items, key=lambda x: x[1] - x[2])
        target = _round_mem(max(used * 2, 128 * MIB))
        fid = _fid(wl.key, "rightsize", name)
        out.setdefault(
            fid,
            Finding(
                id=fid,
                workload=wl,
                category="config",
                title=f"'{name}' requests {_fmt(req)} memory but uses {_fmt(used)}",
                severity=Severity.LOW,
                explanation="The request reserves node capacity nobody uses (cost, and it makes pods harder to "
                "schedule). Lower it after checking peak usage over a full business cycle; metrics-server only "
                "shows the current value.",
                evidence=[Evidence(source="metrics-server", detail=f"{name}: request {_fmt(req)}, using {_fmt(used)}")],
                remediations=[
                    RemediationHint(
                        kind="set-memory-request",
                        params={"container": name, "current": _fmt(req), "proposed": _fmt(target)},
                        summary=f"Lower the memory request of '{name}' to about {_fmt(target)}",
                    )
                ],
            ),
        )
    return list(out.values())


def capacity_summary(snap: Snapshot) -> dict[str, Any] | None:
    """Requested vs used CPU/memory across running pods: the over-provisioning a cost review starts from."""
    if not snap.pod_metrics:
        return None
    by_pod = {(m.namespace, m.pod): m for m in snap.pod_metrics}
    req_cpu = used_cpu = req_mem = used_mem = 0
    for p in snap.pods:
        m = by_pod.get((p.namespace, p.name))
        if m is None or p.phase != "Running":
            continue
        for c in p.app_containers:
            u = m.containers.get(c.name)
            if u is None:
                continue
            req_cpu += _millis(c.resources.cpu_request) or 0
            req_mem += _bytes(c.resources.memory_request) or 0
            used_cpu += u.cpu_millis
            used_mem += u.memory_bytes
    return {
        "cpu": {"requested_m": req_cpu, "used_m": used_cpu, "idle_requested_m": max(0, req_cpu - used_cpu)},
        "memory": {
            "requested": _fmt(req_mem),
            "used": _fmt(used_mem),
            "idle_requested": _fmt(max(0, req_mem - used_mem)),
        },
        "note": "Current usage from metrics-server, not a peak. Idle requests are capacity you pay for but don't use.",
    }
