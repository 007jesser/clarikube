"""Who depends on what: map application workloads to the components (Kafka, Redis, ...) they connect to,
then blame an unhealthy dependency instead of the application when both are failing.

Edges are inferred from env var values that point at a Service DNS name
(``kafka:9092``, ``redis://cache-redis-master.data:6379``, ``http://search.data.svc:9200``,
``events-kafka-0.events-kafka-brokers.data.svc``). Values are parsed in memory only: the output carries the
env var *name* and the Service name, never the value (it may embed credentials).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from clarikube.engine import layers
from clarikube.engine.components import Component, status_of
from clarikube.engine.logsig import LogSignal
from clarikube.models import Evidence, Finding, Pod, RemediationHint, ServiceInfo, Severity, WorkloadRef
from clarikube.source.base import Snapshot

_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


# Log signatures that name the kind of system at fault.
_SIGNAL_KIND = {
    "kafka-isr": "kafka",
    "kafka-unavailable": "kafka",
    "search-block": "opensearch",
    "pg-conn": "postgresql",
}


@dataclass(frozen=True)
class Edge:
    client: WorkloadRef
    component: str  # Component.key
    component_label: str
    service: str
    env_var: str


_HOSTY_ENV = re.compile(r"HOST|URL|URI|ADDR|SERVER|BROKER|ENDPOINT|DSN|BOOTSTRAP|CONNECTION|SERVICE", re.I)


def candidates(value: str) -> list[tuple[str, bool]]:
    """(hostname, strong) pairs from a connection string, URL, or comma-separated broker list.
    ``strong`` = the token had a scheme, a port, or a dotted name (clearly an address, not a word)."""
    out: list[tuple[str, bool]] = []
    for token in re.split(r"[,;\s]+", value.strip()):
        if not token:
            continue
        had_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", token, flags=re.I))
        t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", token, flags=re.I)
        t = t.split("@")[-1]  # drop user:password@
        t = re.split(r"[/?#]", t, maxsplit=1)[0]
        if t.startswith("["):  # IPv6 literal
            continue
        had_port = t.count(":") == 1 and t.rsplit(":", 1)[1].isdigit()
        host = t.rsplit(":", 1)[0] if t.count(":") == 1 else t
        host = host.lower().rstrip(".")
        if host and _HOST.match(host) and not host.replace(".", "").isdigit():
            out.append((host, had_scheme or had_port or "." in host))
    return out


def hosts_in(value: str) -> list[str]:
    """Hostnames that are clearly addresses (scheme, port or dotted name) in a value."""
    return [h for h, strong in candidates(value) if strong]


def _resolve(host: str, client_ns: str, services: list[ServiceInfo]) -> ServiceInfo | None:
    candidates = [host]
    parts = host.split(".")
    if len(parts) > 1:  # StatefulSet pod DNS: pod-0.<headless-svc>.<ns>...
        candidates.append(".".join(parts[1:]))
    for cand in candidates:
        for s in services:
            if cand == s.name and s.namespace == client_ns:
                return s
            if "." in cand and cand in s.dns_names():
                return s
    return None


def build(snap: Snapshot, components: list[Component]) -> list[Edge]:
    by_service: dict[tuple[str, str], Component] = {}
    for comp in components:
        for svc in comp.services:
            by_service[(svc.namespace, svc.name)] = comp
    component_pods = {(p.namespace, p.name) for c in components for p in c.pods}
    edges: dict[tuple[str, str, str], Edge] = {}
    seen_workloads: set[str] = set()
    for p in snap.pods:
        if (p.namespace, p.name) in component_pods or p.workload.key in seen_workloads:
            continue
        seen_workloads.add(p.workload.key)
        for c in p.app_containers:
            for e in c.env:
                if not e.value:
                    continue
                hosty = bool(_HOSTY_ENV.search(e.name))
                for host, strong in candidates(e.value):
                    if not strong and not hosty:
                        continue
                    target = _resolve(host, p.namespace, snap.services)
                    hit = by_service.get((target.namespace, target.name)) if target else None
                    if hit is None or target is None:
                        continue
                    key = (p.workload.key, hit.key, target.name)
                    edges.setdefault(key, Edge(p.workload, hit.key, hit.label, target.name, e.name))
    # Platform components wired by config instead of env: log agents -> their outputs.
    for comp in components:
        for host, plugin in layers.logging_hosts(snap, comp):
            target = _resolve(host, comp.namespace, snap.services)
            hit = by_service.get((target.namespace, target.name)) if target else None
            if hit is None or target is None or hit is comp:
                continue
            key = (comp.ref.key, hit.key, target.name)
            edges.setdefault(key, Edge(comp.ref, hit.key, hit.label, target.name, f"output:{plugin}"))
    return sorted(edges.values(), key=lambda e: (e.client.key, e.component))


def pipeline_findings(
    comp: Component, edges: list[Edge], component_findings: dict[str, list[Finding]]
) -> list[Finding]:
    """A log agent whose destination is unhealthy is losing or buffering logs, even if the agent looks fine."""
    out: list[Finding] = []
    for e in edges:
        if e.client != comp.ref or not e.env_var.startswith("output:"):
            continue
        fs = component_findings.get(e.component, [])
        status = status_of(fs)
        if status not in ("down", "critical", "degraded"):
            continue
        sev = Severity.HIGH if status in ("down", "critical") else Severity.MEDIUM
        fid = hashlib.sha1(f"{comp.key}|pipeline|{e.component}".encode(), usedforsecurity=False).hexdigest()[:10]
        top = [f.title for f in fs if f.category == "reliability"][:2]
        out.append(
            Finding(
                id=fid,
                workload=comp.ref,
                component=comp.label,
                category="reliability",
                title=f"{comp.label}: logs are not being delivered to {e.component_label} ({status})",
                severity=sev,
                explanation=f"{comp.label} ships logs to {e.component_label} via Service {e.service} "
                f"({e.env_var.split(':', 1)[1]} output), which is {status}: "
                + "; ".join(top)
                + ". Logs are buffered and, once retries or buffers run out, dropped. Fix the destination first.",
                evidence=[Evidence(source="dependency", detail=f"output {e.env_var.split(':', 1)[1]} -> {e.service}")]
                + [Evidence(source="component", detail=t) for t in top],
                remediations=[
                    RemediationHint(
                        kind="investigate-component",
                        params={"component": e.component},
                        summary=f"Run diagnose_component on {e.component_label}",
                    )
                ],
            )
        )
    return out


def clients_of(edges: list[Edge], component_key: str) -> list[Edge]:
    return [e for e in edges if e.component == component_key]


def dependencies_of(edges: list[Edge], wl: WorkloadRef) -> list[Edge]:
    return [e for e in edges if e.client == wl]


def upstream_findings(
    wl: WorkloadRef,
    pods: list[Pod],
    own_findings: list[Finding],
    edges: list[Edge],
    component_findings: dict[str, list[Finding]],
    log_signals: list[LogSignal] | None = None,
) -> list[Finding]:
    """If this workload is failing and a component it depends on is unhealthy, say so first."""
    failing = any(f.severity >= Severity.MEDIUM and f.category == "reliability" for f in own_findings) or any(
        not c.ready for p in pods for c in p.app_containers if p.phase != "Succeeded"
    )
    if not failing:
        return []
    signal_hosts = {h for s in (log_signals or []) for h in s.hosts}
    blamed_kinds = {_SIGNAL_KIND[s.kind] for s in (log_signals or []) if s.kind in _SIGNAL_KIND}
    deps = dependencies_of(edges, wl)

    def log_points_at(edge: Edge) -> bool:
        host_hit = any(h == edge.service or h.startswith(edge.service + ".") for h in signal_hosts)
        return host_hit or edge.component.split("/", 1)[0] in blamed_kinds

    pointed = {e.component for e in deps if log_points_at(e)}
    out: list[Finding] = []
    for edge in deps:
        bad = [
            f
            for f in component_findings.get(edge.component, [])
            if f.severity >= Severity.HIGH
            and (f.category == "reliability" or "insync" in f.title or "min.insync" in f.title)
        ]
        log_hit = edge.component in pointed
        if not bad and not log_hit:
            continue
        secondary = bool(pointed) and not log_hit  # the logs blame another dependency
        ev = [
            Evidence(
                source="dependency",
                detail=f"{wl.name} uses {edge.component_label} via Service {edge.service} (env {edge.env_var})",
            )
        ]
        ev += [Evidence(source="component", detail=f"[{f.severity.label}] {f.title}") for f in bad[:3]]
        if log_hit:
            ev += [
                Evidence(source="logs", detail=f"{s.summary}: {s.excerpt}")
                for s in (log_signals or [])
                if any(edge.service in h for h in s.hosts)
                or _SIGNAL_KIND.get(s.kind) == edge.component.split("/", 1)[0]
            ][:2]
        sev = Severity.CRITICAL if any(f.severity == Severity.CRITICAL for f in bad) else Severity.HIGH
        title = (
            f"Likely root cause: {edge.component_label} is unhealthy"
            if bad
            else f"Cannot reach {edge.component_label} ({edge.service})"
        )
        if secondary:
            sev, title = Severity.MEDIUM, f"Dependency {edge.component_label} is also unhealthy"
        expl = (
            f"{wl.name} also depends on {edge.component_label}, which is unhealthy, but its logs point at another "
            "dependency first. Fix that one, then check this."
            if secondary
            else f"{wl.name} depends on {edge.component_label}, which currently reports: "
            + "; ".join(f.title for f in bad[:2])
            + ". Fix the dependency first; restarting or changing "
            f"{wl.name} will not help."
            if bad
            else f"{wl.name}'s logs show connection failures to {edge.service}, the Service of "
            f"{edge.component_label}. Check that component and any NetworkPolicy between them."
        )
        fid = hashlib.sha1(f"{wl.key}|upstream|{edge.component}".encode(), usedforsecurity=False).hexdigest()[:10]
        out.append(
            Finding(
                id=fid,
                workload=wl,
                category="reliability",
                title=title,
                severity=sev,
                explanation=expl,
                evidence=ev,
                remediations=[
                    RemediationHint(
                        kind="investigate-component",
                        params={"component": edge.component},
                        summary=f"Run diagnose_component on {edge.component_label}",
                    )
                ],
            )
        )
    return out
