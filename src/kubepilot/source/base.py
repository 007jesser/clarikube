"""Source interface and the normalized cluster snapshot engines operate on."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from kubepilot import normalize
from kubepilot.models import (
    BindingInfo,
    Event,
    FalcoAlert,
    NetworkPolicyInfo,
    Node,
    Pod,
    ReplicaSetInfo,
    RoleInfo,
    VulnerabilityReport,
    WorkloadRef,
)

Raw = dict[str, Any]


@dataclass
class RawCluster:
    """Raw objects in Kubernetes API JSON shape, as returned by a backend."""

    pods: list[Raw] = field(default_factory=list)
    replicasets: list[Raw] = field(default_factory=list)
    jobs: list[Raw] = field(default_factory=list)
    events: list[Raw] = field(default_factory=list)
    nodes: list[Raw] = field(default_factory=list)
    network_policies: list[Raw] = field(default_factory=list)
    roles: list[Raw] = field(default_factory=list)
    bindings: list[Raw] = field(default_factory=list)
    vulnerability_reports: list[Raw] = field(default_factory=list)


@dataclass
class Snapshot:
    """A normalized, point-in-time view of (part of) the cluster."""

    now: datetime
    pods: list[Pod]
    replicasets: list[ReplicaSetInfo]
    events: list[Event]
    nodes: list[Node]
    network_policies: list[NetworkPolicyInfo]
    roles: list[RoleInfo]
    bindings: list[BindingInfo]
    vulnerability_reports: list[VulnerabilityReport]
    falco_alerts: list[FalcoAlert]
    warnings: list[str] = field(default_factory=list)  # e.g. "Trivy Operator CRDs not found"

    @classmethod
    def build(
        cls,
        raw: RawCluster,
        now: datetime,
        falco: list[FalcoAlert] | None = None,
        warnings: list[str] | None = None,
    ) -> Snapshot:
        owners = normalize.OwnerIndex(raw.replicasets, raw.jobs)
        return cls(
            now=now,
            pods=[normalize.pod(p, owners) for p in raw.pods],
            replicasets=[normalize.replicaset(r, owners) for r in raw.replicasets],
            events=[normalize.event(e) for e in raw.events],
            nodes=[normalize.node(n) for n in raw.nodes],
            network_policies=[normalize.network_policy(n) for n in raw.network_policies],
            roles=[normalize.role(r) for r in raw.roles],
            bindings=[normalize.binding(b) for b in raw.bindings],
            vulnerability_reports=[normalize.vulnerability_report(v, owners) for v in raw.vulnerability_reports],
            falco_alerts=list(falco or []),
            warnings=list(warnings or []),
        )

    # ------------------------------------------------------------ lookups

    def workloads(self) -> list[WorkloadRef]:
        seen: dict[str, WorkloadRef] = {}
        for p in self.pods:
            seen.setdefault(p.workload.key, p.workload)
        return sorted(seen.values(), key=lambda w: w.key)

    def pods_of(self, wl: WorkloadRef) -> list[Pod]:
        return [p for p in self.pods if p.workload == wl]

    def find_workload(self, namespace: str, name: str) -> WorkloadRef | None:
        """Match a workload by name, or by the name of one of its pods."""
        for w in self.workloads():
            if w.namespace == namespace and w.name == name:
                return w
        for p in self.pods:
            if p.namespace == namespace and p.name == name:
                return p.workload
        return None

    def replicasets_of(self, wl: WorkloadRef) -> list[ReplicaSetInfo]:
        rs = [r for r in self.replicasets if r.owner == wl]
        return sorted(rs, key=lambda r: (r.revision or 0, r.created_at or self.now))

    def events_for(self, wl: WorkloadRef) -> list[Event]:
        names = {p.name for p in self.pods_of(wl)} | {r.name for r in self.replicasets_of(wl)} | {wl.name}
        return [e for e in self.events if e.namespace == wl.namespace and e.involved_name in names]


class ClusterSource(Protocol):
    """Backend that yields snapshots. Implementations must be read-only."""

    name: str

    def snapshot(self, namespace: str | None = None) -> Snapshot: ...
