"""Source interface and the normalized cluster snapshot engines operate on."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from kubepilot import normalize
from kubepilot.models import (
    BindingInfo,
    ConfigMapInfo,
    CustomResource,
    Event,
    FalcoAlert,
    FiringAlert,
    HPAInfo,
    IngressClassInfo,
    IngressInfo,
    NamespaceInfo,
    NetworkPolicyInfo,
    Node,
    PDBInfo,
    Pod,
    PodMetricsInfo,
    PVCInfo,
    ReplicaSetInfo,
    RoleInfo,
    ServiceInfo,
    StorageClassInfo,
    VulnerabilityReport,
    WorkloadRef,
    WorkloadSpec,
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
    workloads: list[Raw] = field(default_factory=list)  # Deployments, StatefulSets, DaemonSets
    pvcs: list[Raw] = field(default_factory=list)
    services: list[Raw] = field(default_factory=list)
    pdbs: list[Raw] = field(default_factory=list)
    custom_resources: list[Raw] = field(default_factory=list)
    ingresses: list[Raw] = field(default_factory=list)
    ingress_classes: list[Raw] = field(default_factory=list)
    config_maps: list[Raw] = field(default_factory=list)  # only those of detected platform components
    storage_classes: list[Raw] = field(default_factory=list)
    namespaces: list[Raw] = field(default_factory=list)
    hpas: list[Raw] = field(default_factory=list)
    pod_metrics: list[Raw] = field(default_factory=list)  # metrics.k8s.io, if metrics-server is installed
    server_version: str | None = None


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
    specs: list[WorkloadSpec] = field(default_factory=list)
    pvcs: list[PVCInfo] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    pdbs: list[PDBInfo] = field(default_factory=list)
    custom_resources: list[CustomResource] = field(default_factory=list)
    ingresses: list[IngressInfo] = field(default_factory=list)
    ingress_classes: list[IngressClassInfo] = field(default_factory=list)
    config_maps: list[ConfigMapInfo] = field(default_factory=list)
    storage_classes: list[StorageClassInfo] = field(default_factory=list)
    namespaces: list[NamespaceInfo] = field(default_factory=list)
    hpas: list[HPAInfo] = field(default_factory=list)
    pod_metrics: list[PodMetricsInfo] = field(default_factory=list)
    alerts: list[FiringAlert] = field(default_factory=list)  # Prometheus alerts via Alertmanager webhook
    server_version: str | None = None
    metrics_available: bool = False

    @classmethod
    def build(
        cls,
        raw: RawCluster,
        now: datetime,
        falco: list[FalcoAlert] | None = None,
        warnings: list[str] | None = None,
        alerts: list[FiringAlert] | None = None,
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
            specs=[normalize.workload_spec(w) for w in raw.workloads],
            pvcs=[normalize.pvc(p) for p in raw.pvcs],
            services=[normalize.service(s) for s in raw.services],
            pdbs=[normalize.pdb(p) for p in raw.pdbs],
            custom_resources=[normalize.custom_resource(c) for c in raw.custom_resources],
            ingresses=[normalize.ingress(i) for i in raw.ingresses],
            ingress_classes=[normalize.ingress_class(i) for i in raw.ingress_classes],
            config_maps=[normalize.config_map(c) for c in raw.config_maps],
            storage_classes=[normalize.storage_class(c) for c in raw.storage_classes],
            namespaces=[normalize.namespace(n) for n in raw.namespaces],
            hpas=[normalize.hpa(h) for h in raw.hpas],
            pod_metrics=[normalize.pod_metrics(p) for p in raw.pod_metrics],
            alerts=list(alerts or []),
            server_version=raw.server_version,
            metrics_available=bool(raw.pod_metrics),
        )

    # ------------------------------------------------------------ lookups

    def workloads(self) -> list[WorkloadRef]:
        """Workloads with pods, plus controllers that have none (scaled to zero, or pods blocked by admission)."""
        seen: dict[str, WorkloadRef] = {}
        for p in self.pods:
            seen.setdefault(p.workload.key, p.workload)
        for s in self.specs:
            if s.owner is None:
                seen.setdefault(s.ref.key, s.ref)
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

    def config_map(self, namespace: str, name: str) -> ConfigMapInfo | None:
        return next((c for c in self.config_maps if c.namespace == namespace and c.name == name), None)

    def spec_of(self, wl: WorkloadRef) -> WorkloadSpec | None:
        return next((s for s in self.specs if s.ref == wl), None)

    def events_for(self, wl: WorkloadRef) -> list[Event]:
        names = {p.name for p in self.pods_of(wl)} | {r.name for r in self.replicasets_of(wl)} | {wl.name}
        return [e for e in self.events if e.namespace == wl.namespace and e.involved_name in names]


class ClusterSource(Protocol):
    """Backend that yields snapshots. Implementations must be read-only."""

    name: str

    def snapshot(self, namespace: str | None = None) -> Snapshot: ...


LOG_TAIL_LINES = 200
LOG_LIMIT_BYTES = 64 * 1024


def read_logs(source: object, namespace: str, pod: str, container: str, previous: bool) -> str | None:
    """Tail of a container's log if the source supports it (optional capability). Never raises."""
    fn = getattr(source, "logs", None)
    if fn is None:
        return None
    try:
        text = fn(namespace, pod, container, previous)
    except Exception:
        return None
    return text if isinstance(text, str) else None
