"""Normalized, vendor-neutral models used by all engines.

Raw Kubernetes objects (dicts in API JSON shape) are converted into these by
``kubepilot.normalize``. Engines only ever see these types.
"""

from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class WorkloadRef(BaseModel, frozen=True):
    """A top-level controller (Deployment, StatefulSet, ...) or a bare Pod."""

    kind: str
    namespace: str
    name: str

    @property
    def key(self) -> str:
        return f"{self.kind}/{self.namespace}/{self.name}" if self.namespace else f"{self.kind}/{self.name}"


# ---------------------------------------------------------------- pod state


class ContainerState(BaseModel):
    state: Literal["waiting", "running", "terminated", "unknown"] = "unknown"
    reason: str | None = None
    message: str | None = None
    exit_code: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class Resources(BaseModel):
    cpu_request: str | None = None
    cpu_limit: str | None = None
    memory_request: str | None = None
    memory_limit: str | None = None


class SecurityContext(BaseModel):
    """Effective security context (container overrides pod)."""

    privileged: bool = False
    run_as_non_root: bool | None = None
    run_as_user: int | None = None
    allow_privilege_escalation: bool | None = None
    read_only_root_filesystem: bool | None = None
    capabilities_add: list[str] = Field(default_factory=list)
    capabilities_drop: list[str] = Field(default_factory=list)

    @property
    def may_run_as_root(self) -> bool:
        if self.run_as_user is not None:
            return self.run_as_user == 0
        return self.run_as_non_root is not True


class EnvVar(BaseModel):
    """An env var. ``value`` is kept only for internal analysis (dependency hosts, JVM heap,
    insecure flags) and must NEVER be returned to a model: it may hold a literal secret."""

    name: str
    value: str | None = Field(default=None, repr=False)
    from_secret: bool = False
    from_configmap: bool = False


class Container(BaseModel):
    name: str
    image: str
    init: bool = False
    env: list[EnvVar] = Field(default_factory=list, repr=False)
    args: list[str] = Field(default_factory=list, repr=False)  # command + args, internal only
    ports: list[int] = Field(default_factory=list)
    resources: Resources = Field(default_factory=Resources)
    security: SecurityContext = Field(default_factory=SecurityContext)
    has_liveness_probe: bool = False
    has_readiness_probe: bool = False
    ready: bool = False
    restart_count: int = 0
    state: ContainerState = Field(default_factory=ContainerState)
    last_state: ContainerState = Field(default_factory=ContainerState)
    image_id: str | None = None


class Volume(BaseModel):
    name: str
    kind: str  # hostPath, secret, configMap, emptyDir, persistentVolumeClaim, projected, ...
    source: str | None = None  # path / secret name / configmap name / claim name


class Pod(BaseModel):
    namespace: str
    name: str
    uid: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    phase: str = "Unknown"
    node: str | None = None
    service_account: str = "default"
    automount_sa_token: bool = True
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    containers: list[Container] = Field(default_factory=list)
    volumes: list[Volume] = Field(default_factory=list)
    owner: WorkloadRef | None = None  # resolved top-level controller
    replicaset: str | None = None  # direct owner when it's a ReplicaSet
    created_at: datetime | None = None
    conditions: dict[str, str] = Field(default_factory=dict)  # type -> status
    unschedulable_message: str | None = None

    @property
    def workload(self) -> WorkloadRef:
        return self.owner or WorkloadRef(kind="Pod", namespace=self.namespace, name=self.name)

    @property
    def app_containers(self) -> list[Container]:
        return [c for c in self.containers if not c.init]


class Event(BaseModel):
    namespace: str
    involved_kind: str
    involved_name: str
    type: str = "Normal"  # Normal | Warning
    reason: str = ""
    message: str = ""
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class ReplicaSetInfo(BaseModel):
    namespace: str
    name: str
    owner: WorkloadRef | None
    revision: int | None = None
    created_at: datetime | None = None
    replicas: int = 0
    containers: list[Container] = Field(default_factory=list)  # from pod template


class Node(BaseModel):
    name: str
    ready: bool = True
    conditions: dict[str, str] = Field(default_factory=dict)
    allocatable_cpu: str | None = None
    allocatable_memory: str | None = None
    taints: list[str] = Field(default_factory=list)
    kubelet_version: str | None = None


class WorkloadSpec(BaseModel):
    """Desired vs. actual state of a controller (Deployment, StatefulSet, DaemonSet)."""

    kind: str
    namespace: str
    name: str
    labels: dict[str, str] = Field(default_factory=dict)
    selector: dict[str, str] = Field(default_factory=dict)  # matchLabels
    replicas: int = 1
    ready_replicas: int = 0
    containers: list[Container] = Field(default_factory=list)  # from the pod template
    volume_claim_templates: list[str] = Field(default_factory=list)  # StatefulSet claim names
    template_volumes: list[Volume] = Field(default_factory=list)
    service_name: str | None = None  # StatefulSet governing service
    owner: WorkloadRef | None = None  # e.g. operator CR owning a StatefulSet
    tolerations: list[dict[str, str]] = Field(default_factory=list)  # pod template tolerations

    @property
    def ref(self) -> WorkloadRef:
        return WorkloadRef(kind=self.kind, namespace=self.namespace, name=self.name)


class PVCInfo(BaseModel):
    namespace: str
    name: str
    phase: str = "Unknown"  # Pending | Bound | Lost
    storage_class: str | None = None
    requested: str | None = None
    capacity: str | None = None


class ServicePort(BaseModel):
    port: int
    target_port: str | None = None
    node_port: int | None = None
    name: str | None = None


class ServiceInfo(BaseModel):
    namespace: str
    name: str
    type: str = "ClusterIP"  # ClusterIP | NodePort | LoadBalancer | ExternalName
    selector: dict[str, str] = Field(default_factory=dict)
    ports: list[ServicePort] = Field(default_factory=list)
    headless: bool = False
    external: bool = False  # LoadBalancer/NodePort or externalIPs: reachable from outside the cluster
    lb_assigned: bool | None = None  # LoadBalancer only: has the cloud/LB controller assigned an address?

    def dns_names(self) -> set[str]:
        n, ns = self.name, self.namespace
        return {n, f"{n}.{ns}", f"{n}.{ns}.svc", f"{n}.{ns}.svc.cluster.local"}


class PDBInfo(BaseModel):
    namespace: str
    name: str
    selector: LabelSelector
    min_available: str | None = None
    max_unavailable: str | None = None
    disruptions_allowed: int | None = None


class StorageClassInfo(BaseModel):
    name: str
    provisioner: str = ""
    default: bool = False
    binding_mode: str = "Immediate"


class NamespaceInfo(BaseModel):
    name: str
    labels: dict[str, str] = Field(default_factory=dict)


class HPAInfo(BaseModel):
    namespace: str
    name: str
    target_kind: str = ""
    target_name: str = ""
    min_replicas: int = 1
    max_replicas: int = 1
    current_replicas: int = 0
    desired_replicas: int = 0
    conditions: list[Condition] = Field(default_factory=list)


class ContainerUsage(BaseModel):
    cpu_millis: int = 0
    memory_bytes: int = 0


class PodMetricsInfo(BaseModel):
    namespace: str
    pod: str
    containers: dict[str, ContainerUsage] = Field(default_factory=dict)


class FiringAlert(BaseModel):
    """A Prometheus alert received from Alertmanager's webhook."""

    name: str
    status: str = "firing"
    severity: str = "warning"
    namespace: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    summary: str = ""
    starts_at: datetime | None = None
    fingerprint: str = ""


class IngressPath(BaseModel):
    host: str | None = None
    path: str = "/"
    service: str | None = None
    port: str | None = None


class IngressInfo(BaseModel):
    namespace: str
    name: str
    ingress_class: str | None = None
    paths: list[IngressPath] = Field(default_factory=list)
    tls_hosts: list[str] = Field(default_factory=list)
    tls_secrets: list[str] = Field(default_factory=list)
    annotations: dict[str, str] = Field(default_factory=dict, repr=False)  # parsed internally, never echoed whole

    @property
    def hosts(self) -> list[str]:
        return sorted({p.host for p in self.paths if p.host})


class IngressClassInfo(BaseModel):
    name: str
    controller: str = ""
    default: bool = False


class ConfigMapInfo(BaseModel):
    """Configuration of detected platform components (Fluent Bit, ingress-nginx, ...).

    ``data`` is parsed in memory only and is NEVER returned to a model: config files can embed credentials."""

    namespace: str
    name: str
    data: dict[str, str] = Field(default_factory=dict, repr=False)


class Condition(BaseModel):
    type: str
    status: str
    reason: str | None = None
    message: str | None = None


class CustomResource(BaseModel):
    """An operator-managed object (Strimzi Kafka, RabbitmqCluster, CNPG Cluster, ...)."""

    group: str
    kind: str
    namespace: str
    name: str
    labels: dict[str, str] = Field(default_factory=dict)
    spec: dict[str, Any] = Field(default_factory=dict, repr=False)
    status: dict[str, Any] = Field(default_factory=dict, repr=False)
    conditions: list[Condition] = Field(default_factory=list)


# ---------------------------------------------------------------- security inputs


class LabelSelector(BaseModel):
    match_labels: dict[str, str] = Field(default_factory=dict)
    match_expressions: list[dict[str, object]] = Field(default_factory=list)


class NetworkPolicyInfo(BaseModel):
    namespace: str
    name: str
    pod_selector: LabelSelector
    policy_types: list[str] = Field(default_factory=list)  # Ingress / Egress


class PolicyRule(BaseModel):
    api_groups: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    verbs: list[str] = Field(default_factory=list)
    resource_names: list[str] = Field(default_factory=list)


class RoleInfo(BaseModel):
    kind: Literal["Role", "ClusterRole"]
    namespace: str | None
    name: str
    rules: list[PolicyRule] = Field(default_factory=list)


class Subject(BaseModel):
    kind: str
    name: str
    namespace: str | None = None


class BindingInfo(BaseModel):
    kind: Literal["RoleBinding", "ClusterRoleBinding"]
    namespace: str | None
    name: str
    role_kind: Literal["Role", "ClusterRole"]
    role_name: str
    subjects: list[Subject] = Field(default_factory=list)


class Vulnerability(BaseModel):
    id: str
    severity: Severity
    package: str = ""
    installed_version: str = ""
    fixed_version: str | None = None
    title: str = ""
    score: float | None = None


class VulnerabilityReport(BaseModel):
    namespace: str
    workload: WorkloadRef | None
    container: str
    image: str
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)

    def count(self, severity: Severity) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == severity)


class FalcoAlert(BaseModel):
    time: datetime
    rule: str
    priority: str  # Emergency, Alert, Critical, Error, Warning, Notice, Informational, Debug
    output: str = ""
    namespace: str | None = None
    pod: str | None = None
    container: str | None = None
    image: str | None = None
    tags: list[str] = Field(default_factory=list)

    @property
    def severity(self) -> Severity:
        return FALCO_PRIORITY.get(self.priority.lower(), Severity.LOW)


FALCO_PRIORITY: dict[str, Severity] = {
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "notice": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.INFO,
}


# ---------------------------------------------------------------- outputs


class Evidence(BaseModel):
    source: str  # e.g. "pod-status", "event", "falco", "trivy", "rbac", "rollout"
    detail: str
    at: datetime | None = None


class RemediationHint(BaseModel):
    """Machine-readable pointer to a remediation generator in ``kubepilot.remediation``."""

    kind: str  # e.g. "raise-memory-limit", "harden-security-context", "default-deny-netpol"
    params: dict[str, str] = Field(default_factory=dict)
    summary: str


class Finding(BaseModel):
    id: str
    workload: WorkloadRef
    component: str | None = None  # e.g. "kafka data/events" when raised by a component pack
    category: Literal["reliability", "security", "config"]
    title: str
    severity: Severity
    explanation: str
    evidence: list[Evidence] = Field(default_factory=list)
    remediations: list[RemediationHint] = Field(default_factory=list)


class SecurityIncident(BaseModel):
    id: str
    workload: WorkloadRef
    score: int
    severity: Severity
    summary: str
    signals: list[str] = Field(default_factory=list)  # human-readable signal list w/ points
    evidence: list[Evidence] = Field(default_factory=list)
    suppressed_alerts: int = 0
    remediations: list[RemediationHint] = Field(default_factory=list)


HPAInfo.model_rebuild()
