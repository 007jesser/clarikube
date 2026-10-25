"""Stateful component packs: detect middleware (Kafka, RabbitMQ, OpenSearch/Elasticsearch, PostgreSQL,
Redis, MongoDB, ZooKeeper) in the cluster and diagnose it with deterministic checks.

Detection works two ways and merges the results:
1. **Operator resources**: Strimzi ``Kafka``, ``RabbitmqCluster``, ``OpenSearchCluster``, ECK ``Elasticsearch``,
   CloudNativePG ``Cluster``, Zalando ``postgresql``, ``MongoDBCommunity``, OT-Redis.
2. **Images** of Deployments/StatefulSets (Bitnami charts, official images, hand-written manifests),
   grouped by ``app.kubernetes.io/instance``.

Everything is read from the snapshot (Kubernetes objects only). Env values are inspected for
configuration (heap size, replication factors, insecure flags) but never returned.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from kubemedic import quantity
from kubemedic.engine import layers, selectors
from kubemedic.models import (
    Container,
    CustomResource,
    Evidence,
    Finding,
    LabelSelector,
    Pod,
    PVCInfo,
    RemediationHint,
    ServiceInfo,
    ServicePort,
    Severity,
    WorkloadRef,
    WorkloadSpec,
)
from kubemedic.sanitize import clean
from kubemedic.source.base import Snapshot

KINDS = ("kafka", "zookeeper", "rabbitmq", "opensearch", "elasticsearch", "postgresql", "redis", "mongodb")
DISPLAY = {
    "kafka": "Kafka",
    "zookeeper": "ZooKeeper",
    "rabbitmq": "RabbitMQ",
    "opensearch": "OpenSearch",
    "elasticsearch": "Elasticsearch",
    "postgresql": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
}
DISPLAY.update(layers.PLATFORM_DISPLAY)
# Systems whose availability depends on a majority of members being up.
QUORUM_KINDS = {"kafka", "zookeeper", "rabbitmq", "opensearch", "elasticsearch", "mongodb"}
JVM_KINDS = {"kafka", "zookeeper", "opensearch", "elasticsearch"}
CLIENT_PORTS = {
    "kafka": {9092, 9093, 9094},
    "zookeeper": {2181},
    "rabbitmq": {5672, 5671},
    "opensearch": {9200},
    "elasticsearch": {9200},
    "postgresql": {5432},
    "redis": {6379, 26379},
    "mongodb": {27017},
}
ADMIN_PORTS = {"rabbitmq": {15672}, "opensearch": {9600}, "elasticsearch": {9300}}

_EXCLUDE = re.compile(r"exporter|operator|dashboards|kibana|insight|commander|express|agent|admin|ui$|proxy|bouncer")

# CR kind -> (component kind, pod label keys that name the instance)
_CR_KINDS: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("kafka.strimzi.io", "Kafka"): ("kafka", ("strimzi.io/cluster",)),
    ("rabbitmq.com", "RabbitmqCluster"): ("rabbitmq", ("app.kubernetes.io/name",)),
    ("opensearch.org", "OpenSearchCluster"): (
        "opensearch",
        ("opensearch.org/opensearch-cluster", "opster.io/opensearch-cluster"),
    ),
    ("opensearch.opster.io", "OpenSearchCluster"): (
        "opensearch",
        ("opensearch.org/opensearch-cluster", "opster.io/opensearch-cluster"),
    ),
    ("elasticsearch.k8s.elastic.co", "Elasticsearch"): (
        "elasticsearch",
        ("elasticsearch.k8s.elastic.co/cluster-name",),
    ),
    ("postgresql.cnpg.io", "Cluster"): ("postgresql", ("cnpg.io/cluster", "postgresql")),
    ("acid.zalan.do", "postgresql"): ("postgresql", ("cluster-name",)),
    ("mongodbcommunity.mongodb.com", "MongoDBCommunity"): ("mongodb", ("app",)),
    ("redis.redis.opstreelabs.in", "RedisCluster"): ("redis", ("app", "redis_setup_type")),
    ("redis.redis.opstreelabs.in", "RedisReplication"): ("redis", ("app",)),
}
_OPERATOR_NAME = {
    "kafka.strimzi.io": "Strimzi operator",
    "rabbitmq.com": "RabbitMQ cluster operator",
    "opensearch.org": "OpenSearch operator",
    "opensearch.opster.io": "OpenSearch operator",
    "elasticsearch.k8s.elastic.co": "ECK operator",
    "postgresql.cnpg.io": "CloudNativePG operator",
    "acid.zalan.do": "Zalando postgres-operator",
    "mongodbcommunity.mongodb.com": "MongoDB community operator",
    "redis.redis.opstreelabs.in": "OT Redis operator",
}


def classify_image(image: str) -> str | None:
    """Map a container image to a component kind (or None)."""
    platform = layers.classify_platform_image(image)
    if platform:
        return platform
    repo = image.split("@")[0]
    last = repo.rsplit("/", 1)[-1].split(":")[0].lower()
    if _EXCLUDE.search(last):
        return None
    if last in ("kafka", "cp-kafka", "cp-server"):
        return "kafka"
    if last in ("zookeeper", "cp-zookeeper"):
        return "zookeeper"
    if last.startswith("rabbitmq"):
        return "rabbitmq"
    if last == "opensearch":
        return "opensearch"
    if last == "elasticsearch":
        return "elasticsearch"
    if last.startswith(("postgres", "spilo", "postgis", "timescaledb")):
        return "postgresql"
    if last.startswith(("redis", "valkey")):
        return "redis"
    if last.startswith("mongo"):
        return "mongodb"
    return None


def _main_container(containers: list[Container], kind: str) -> Container | None:
    return next((c for c in containers if not c.init and classify_image(c.image) == kind), None)


@dataclass
class Component:
    kind: str
    namespace: str
    name: str
    managed_by: str
    cr: CustomResource | None = None
    specs: list[WorkloadSpec] = field(default_factory=list)
    pods: list[Pod] = field(default_factory=list)
    services: list[ServiceInfo] = field(default_factory=list)
    pools: list[CustomResource] = field(default_factory=list)  # Strimzi KafkaNodePools of this Kafka

    @property
    def key(self) -> str:
        return f"{self.kind}/{self.namespace}/{self.name}"

    @property
    def layer(self) -> str:
        return layers.layer_of(self.kind)

    @property
    def label(self) -> str:
        return f"{DISPLAY[self.kind]} {self.namespace}/{self.name}"

    @property
    def ref(self) -> WorkloadRef:
        """What remediation should target: the CR for operator-managed components, else the controller."""
        if self.cr is not None:
            return WorkloadRef(kind=self.cr.kind, namespace=self.namespace, name=self.cr.name)
        if self.specs:
            return self.specs[0].ref
        if self.pods:
            return self.pods[0].workload
        return WorkloadRef(kind="Component", namespace=self.namespace, name=self.name)

    @property
    def containers(self) -> list[Container]:
        out: list[Container] = []
        for s in self.specs:
            c = _main_container(s.containers, self.kind)
            if c:
                out.append(c)
        if not out:
            for p in self.pods[:1]:
                c = _main_container(p.containers, self.kind)
                if c:
                    out.append(c)
        return out

    @property
    def version(self) -> str | None:
        for c in self.containers:
            tag = c.image.split("@")[0].rsplit("/", 1)[-1]
            if ":" in tag:
                return tag.split(":", 1)[1]
        if self.cr is not None:
            v = self.cr.spec.get("version") or (self.cr.spec.get("kafka") or {}).get("version")
            return str(v) if v else None
        return None

    @property
    def desired(self) -> int:
        if self.pools:  # Strimzi KRaft: members are defined by node pools, not the Kafka resource
            return sum(_int(p.spec.get("replicas")) for p in self.pools)
        if self.specs:
            return sum(s.replicas for s in self.specs)
        if self.cr is not None:
            n = _cr_desired(self.cr)
            if n is not None:
                return n
        return len(self.pods)

    @property
    def ready(self) -> int:
        return sum(1 for p in self.pods if _pod_ready(p, self.kind))

    @property
    def brokers_desired(self) -> int:
        """Kafka brokers (controller-only node pools excluded)."""
        if self.pools:
            return sum(_int(p.spec.get("replicas")) for p in self.pools if "broker" in (p.spec.get("roles") or []))
        return self.desired

    @property
    def brokers_ready(self) -> int:
        def broker(p: Pod) -> bool:
            role = p.labels.get("strimzi.io/broker-role")
            return role is None or role == "true"

        return sum(1 for p in self.pods if broker(p) and _pod_ready(p, self.kind))

    @property
    def pod_labels_selector(self) -> dict[str, str]:
        """Smallest common label set across the component's pods (for PDB / NetworkPolicy fixes)."""
        if not self.pods:
            return self.specs[0].selector if self.specs else {}
        common = dict(self.pods[0].labels)
        for p in self.pods[1:]:
            common = {k: v for k, v in common.items() if p.labels.get(k) == v}
        for volatile in (
            "pod-template-hash",
            "controller-revision-hash",
            "statefulset.kubernetes.io/pod-name",
            "apps.kubernetes.io/pod-index",
            "strimzi.io/pod-name",
        ):
            common.pop(volatile, None)
        return common


def _int(v: object, default: int = 0) -> int:
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return default


def _cr_desired(cr: CustomResource) -> int | None:
    s = cr.spec
    try:
        if cr.kind == "Kafka":
            kafka = s.get("kafka") or {}
            return int(kafka["replicas"]) if "replicas" in kafka else None
        if cr.kind == "RabbitmqCluster":
            return int(s.get("replicas", 1))
        if cr.kind == "OpenSearchCluster":
            return sum(int(p.get("replicas", 0)) for p in s.get("nodePools") or [])
        if cr.kind == "Elasticsearch":
            return sum(int(n.get("count", 0)) for n in s.get("nodeSets") or [])
        if cr.kind == "Cluster":
            return int(s.get("instances", 1))
        if cr.kind == "postgresql":
            return int(s.get("numberOfInstances", 1))
        if cr.kind == "MongoDBCommunity":
            return int(s.get("members", 1))
        if cr.kind == "RedisCluster":  # OT operator: leaders + followers, each defaulting to clusterSize
            size = int(s.get("clusterSize", 1))
            leaders = (s.get("redisLeader") or {}).get("replicas")
            followers = (s.get("redisFollower") or {}).get("replicas")
            return int(leaders if leaders is not None else size) + int(followers if followers is not None else size)
        if cr.kind == "RedisReplication":
            return int(s.get("clusterSize", 1))
    except (TypeError, ValueError):
        return None
    return None


def _pod_ready(p: Pod, kind: str) -> bool:
    c = _main_container(p.containers, kind)
    if c is None:
        app = p.app_containers
        return p.phase == "Running" and bool(app) and all(x.ready for x in app)
    return p.phase == "Running" and c.ready


def _labels_match(sel: dict[str, str], labels: dict[str, str]) -> bool:
    return bool(sel) and all(labels.get(k) == v for k, v in sel.items())


# ---------------------------------------------------------------- detection


def detect(snap: Snapshot) -> list[Component]:
    comps: list[Component] = []
    claimed_pods: set[tuple[str, str]] = set()
    claimed_specs: set[str] = set()

    # 1) operator-managed
    current_os = {(c.namespace, c.name) for c in snap.custom_resources if c.group == "opensearch.org"}
    for cr in snap.custom_resources:
        entry = _CR_KINDS.get((cr.group, cr.kind))
        if entry is None:
            continue
        if cr.group == "opensearch.opster.io" and (cr.namespace, cr.name) in current_os:
            continue  # deprecated group, mirrored by the operator into opensearch.org
        kind, label_keys = entry
        comp = Component(
            kind=kind, namespace=cr.namespace, name=cr.name, managed_by=_OPERATOR_NAME.get(cr.group, cr.group), cr=cr
        )
        for p in snap.pods:
            if p.namespace != cr.namespace or (p.namespace, p.name) in claimed_pods:
                continue
            names = (cr.name, f"{cr.name}-svc", f"{cr.name}-leader", f"{cr.name}-follower")
            if not any(p.labels.get(k) in names for k in label_keys):
                continue
            if kind == "kafka" and not _strimzi_kafka_node(p, cr.name):
                continue
            if _main_container(p.containers, kind) is None and kind != "postgresql":
                continue
            comp.pods.append(p)
            claimed_pods.add((p.namespace, p.name))
        if cr.kind == "Kafka":
            comp.pools = [
                np
                for np in snap.custom_resources
                if np.kind == "KafkaNodePool"
                and np.namespace == cr.namespace
                and np.labels.get("strimzi.io/cluster") == cr.name
            ]
        for s in snap.specs:
            owned = s.owner is not None and s.owner.kind == cr.kind and s.owner.name == cr.name
            if s.namespace == cr.namespace and (owned or any(s.ref == p.workload for p in comp.pods)):
                comp.specs.append(s)
                claimed_specs.add(s.ref.key)
        comps.append(comp)

    # 2) image-based (Helm charts, plain manifests)
    groups: dict[tuple[str, str, str], Component] = {}
    for s in snap.specs:
        if s.ref.key in claimed_specs:
            continue
        skind = next((k for c in s.containers if not c.init and (k := classify_image(c.image))), None)
        if skind is None or (s.kind == "DaemonSet" and skind not in layers.DAEMON_KINDS):
            continue
        instance = s.labels.get("app.kubernetes.io/instance") or s.labels.get("release") or s.name
        if skind in layers.CATALOG and skind not in layers.EDGE_KINDS | layers.LOGGING_KINDS:
            # multi-deployment tools (argocd-server, argocd-repo-server, ...) are one component per namespace
            instance = s.labels.get("app.kubernetes.io/part-of") or layers.PLATFORM_DISPLAY[skind].split()[0].lower()
        gkey = (skind, s.namespace, instance)
        if gkey not in groups:
            chart = s.labels.get("helm.sh/chart")
            managed = (
                f"Helm ({chart})"
                if chart
                else ("Helm" if s.labels.get("app.kubernetes.io/managed-by") == "Helm" else "manifests")
            )
            groups[gkey] = Component(kind=skind, namespace=s.namespace, name=instance, managed_by=managed)
        groups[gkey].specs.append(s)
        claimed_specs.add(s.ref.key)
    for comp in groups.values():
        refs = {s.ref for s in comp.specs}
        comp.pods = [p for p in snap.pods if p.workload in refs and (p.namespace, p.name) not in claimed_pods]
        claimed_pods.update((p.namespace, p.name) for p in comp.pods)
        comps.append(comp)

    # 3) bare pods (no controller spec in the snapshot, e.g. partial captures)
    loose: dict[tuple[str, str, str], Component] = {}
    for p in snap.pods:
        if (p.namespace, p.name) in claimed_pods or p.phase in ("Succeeded", "Failed"):
            continue
        pkind = next((k for c in p.app_containers if (k := classify_image(c.image))), None)
        if pkind is None:
            continue
        wl = p.workload
        gkey = (pkind, p.namespace, p.labels.get("app.kubernetes.io/instance") or wl.name)
        loose.setdefault(gkey, Component(kind=pkind, namespace=p.namespace, name=gkey[2], managed_by="manifests"))
        loose[gkey].pods.append(p)
    comps.extend(loose.values())

    # services that select the component's pods
    for comp in comps:
        comp.services = [
            svc
            for svc in snap.services
            if svc.namespace == comp.namespace and any(_labels_match(svc.selector, p.labels) for p in comp.pods)
        ]
        if not comp.services and comp.cr is not None:  # pods may be missing; fall back on naming convention
            comp.services = [s for s in snap.services if s.namespace == comp.namespace and s.name.startswith(comp.name)]
    return sorted(comps, key=lambda c: c.key)


def _strimzi_kafka_node(p: Pod, cluster: str) -> bool:
    if p.labels.get("strimzi.io/broker-role") == "true" or p.labels.get("strimzi.io/controller-role") == "true":
        return True
    name = p.labels.get("strimzi.io/name", "")
    return name == f"{cluster}-kafka" or bool(p.labels.get("strimzi.io/pool-name"))


# ---------------------------------------------------------------- config helpers (internal only)


def env_value(comp: Component, *names: str) -> str | None:
    wanted = {n.upper() for n in names}
    for c in comp.containers:
        for e in c.env:
            if e.name.upper() in wanted and e.value is not None:
                return e.value
    return None


def _all_args(comp: Component) -> list[str]:
    out: list[str] = []
    for c in comp.containers:
        out.extend(c.args)
        out.extend(e.value for e in c.env if e.value)
    return out


_XMX = re.compile(r"-Xmx(\d+)([kKmMgG]?)")


@dataclass(frozen=True)
class Sizing:
    """Heap and memory limit of one sizing unit (a whole component, or one Strimzi node pool)."""

    scope: str  # "" or "node pool <name>"
    heap: int | None
    limit: int | None
    target: dict[str, str]  # extra hint params naming the resource to edit


def _limit_of(resources: object) -> int | None:
    lim = ((resources or {}).get("limits") or {}).get("memory") if isinstance(resources, dict) else None
    return int(quantity.parse(str(lim))) if lim else None


def sizings(comp: Component) -> list[Sizing]:
    if comp.pools and comp.cr is not None:
        base_xmx = ((comp.cr.spec.get("kafka") or {}).get("jvmOptions") or {}).get("-Xmx")
        out = []
        for np in comp.pools:
            xmx = (np.spec.get("jvmOptions") or {}).get("-Xmx") or base_xmx
            out.append(
                Sizing(
                    scope=f"node pool {np.name}",
                    heap=_heap_to_bytes(str(xmx)) if xmx else None,
                    limit=_limit_of(np.spec.get("resources")),
                    target={"target_kind": "KafkaNodePool", "target_name": np.name},
                )
            )
        return out
    return [Sizing(scope="", heap=jvm_heap_bytes(comp), limit=memory_limit_bytes(comp), target={})]


def jvm_heap_bytes(comp: Component) -> int | None:
    if comp.cr is not None and comp.cr.kind == "Kafka":
        xmx = ((comp.cr.spec.get("kafka") or {}).get("jvmOptions") or {}).get("-Xmx")
        if xmx:
            return _heap_to_bytes(str(xmx))
    for text in _all_args(comp):
        m = _XMX.search(text)
        if m:
            return _heap_to_bytes(m.group(1) + m.group(2))
    return None


def _heap_to_bytes(v: str) -> int | None:
    m = re.fullmatch(r"(\d+)([kKmMgG]?)", v.strip())
    if not m:
        return None
    mult = {"": 1, "k": 2**10, "m": 2**20, "g": 2**30}[m.group(2).lower()]
    return int(m.group(1)) * mult


def memory_limit_bytes(comp: Component) -> int | None:
    if comp.cr is not None and comp.cr.kind == "Kafka":
        lim = (((comp.cr.spec.get("kafka") or {}).get("resources") or {}).get("limits") or {}).get("memory")
        if lim:
            return int(quantity.parse(str(lim)))
    for c in comp.containers:
        if c.resources.memory_limit:
            return int(quantity.parse(c.resources.memory_limit))
    return None


def kafka_config(comp: Component) -> dict[str, str]:
    """Broker config from the Strimzi CR or Bitnami/Confluent/Apache env conventions."""
    cfg: dict[str, str] = {}
    if comp.cr is not None and comp.cr.kind == "Kafka":
        cfg.update({k: str(v) for k, v in ((comp.cr.spec.get("kafka") or {}).get("config") or {}).items()})
    for c in comp.containers:
        for e in c.env:
            if e.value is None:
                continue
            n = e.name.upper()
            for prefix in ("KAFKA_CFG_", "KAFKA_"):
                if n.startswith(prefix):
                    key = n[len(prefix) :].lower().replace("_", ".")
                    cfg.setdefault(key, e.value)
                    break
    return cfg


def _truthy(v: str | None) -> bool:
    return v is not None and v.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- checks


def _fid(comp: Component, code: str) -> str:
    return hashlib.sha1(f"{comp.key}|{code}".encode(), usedforsecurity=False).hexdigest()[:10]


def _finding(
    comp: Component,
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
        id=_fid(comp, code),
        workload=comp.ref,
        component=comp.label,
        category=category,  # type: ignore[arg-type]
        title=title,
        severity=sev,
        explanation=expl,
        evidence=evidence or [],
        remediations=hints or [],
    )


def _pod_problem(p: Pod) -> str:
    if p.unschedulable_message:
        return f"Pending: {clean(p.unschedulable_message, 200)}"
    for c in p.app_containers:
        if c.state.reason:
            last = f", last exit: {c.last_state.reason}" if c.last_state.reason else ""
            return f"{c.state.reason}{last} (restarts={c.restart_count})"
        if not c.ready:
            return f"container {c.name} not ready"
    return p.phase


def _check_availability(comp: Component) -> list[Finding]:
    d, r = comp.desired, comp.ready
    if d == 0 or r >= d:
        return []
    bad = [p for p in comp.pods if not _pod_ready(p, comp.kind)]
    ev = [Evidence(source="pod-status", detail=f"{p.name}: {_pod_problem(p)}") for p in bad[:6]]
    if r == 0:
        return [
            _finding(
                comp,
                "down",
                f"{comp.label} is down (0/{d} ready)",
                Severity.CRITICAL,
                f"No {DISPLAY[comp.kind]} member is ready. Every client of this {DISPLAY[comp.kind]} is affected.",
                evidence=ev,
            )
        ]
    return [
        _finding(
            comp,
            "degraded",
            f"{comp.label} is degraded ({r}/{d} ready)",
            Severity.HIGH,
            f"{d - r} of {d} members are not ready; redundancy is reduced and a further failure may cause an outage.",
            evidence=ev,
        )
    ]


def _quorum_members(comp: Component) -> int:
    """Members that vote: masters/controllers when the topology says so, else all members."""
    cr = comp.cr
    if cr is not None and cr.kind == "OpenSearchCluster":
        n = sum(
            int(p.get("replicas", 0))
            for p in cr.spec.get("nodePools") or []
            if {"master", "cluster_manager"} & set(p.get("roles") or [])
        )
        return n or comp.desired
    if cr is not None and cr.kind == "Elasticsearch":
        n = 0
        for ns in cr.spec.get("nodeSets") or []:
            roles = (ns.get("config") or {}).get("node.roles")
            if roles is None or "master" in roles:
                n += int(ns.get("count", 0))
        return n or comp.desired
    return comp.desired


def _check_quorum(comp: Component) -> list[Finding]:
    if comp.kind not in QUORUM_KINDS:
        return []
    voters = _quorum_members(comp)
    out: list[Finding] = []
    if voters >= 3 and comp.ready < voters // 2 + 1 and comp.ready < comp.desired:
        out.append(
            _finding(
                comp,
                "quorum",
                f"{comp.label} has lost quorum",
                Severity.CRITICAL,
                f"Only {comp.ready} of {voters} voting members are ready; a majority "
                f"({voters // 2 + 1}) is required, so the cluster cannot elect a leader or accept "
                "writes safely.",
            )
        )
    if voters in (2, 4):
        out.append(
            _finding(
                comp,
                "even-quorum",
                f"{comp.label} has an even number of voting members ({voters})",
                Severity.MEDIUM,
                f"{voters} members tolerate the same number of failures as {voters - 1}: a majority "
                f"is {voters // 2 + 1}. With {voters}, losing {voters // 2} members (or a network "
                "split) stops the cluster. Use an odd number (3 or 5).",
                category="config",
            )
        )
    return out


def _check_single(comp: Component) -> list[Finding]:
    if comp.desired != 1:
        return []
    sev = Severity.LOW if comp.kind == "redis" else Severity.MEDIUM
    return [
        _finding(
            comp,
            "single",
            f"{comp.label} runs a single instance",
            sev,
            "Any restart, crash or node drain is a full outage for its clients, and there is no replica "
            "to fail over to.",
            category="config",
        )
    ]


def _component_pvcs(snap: Snapshot, comp: Component) -> list[PVCInfo]:
    names = {p.name for p in comp.pods}
    prefixes = [f"{vct}-{s.name}-" for s in comp.specs for vct in s.volume_claim_templates]
    return [
        c
        for c in snap.pvcs
        if c.namespace == comp.namespace
        and (
            any(c.name.endswith(n) for n in names)
            or any(c.name.startswith(pfx) for pfx in prefixes)
            or (comp.cr is not None and c.name.startswith(f"data-{comp.name}"))
        )
    ]


def _check_storage(snap: Snapshot, comp: Component) -> list[Finding]:
    out: list[Finding] = []
    for c in _component_pvcs(snap, comp):
        if c.phase == "Pending":
            out.append(
                _finding(
                    comp,
                    f"pvc-pending-{c.name}",
                    f"{comp.label}: volume {c.name} is not provisioned",
                    Severity.HIGH,
                    f"PersistentVolumeClaim {c.name} is Pending (storage class "
                    f"{c.storage_class or 'default'}): the member using it cannot start. "
                    + (
                        f"StorageClass {c.storage_class} does not exist in the cluster, so no volume will ever be "
                        "provisioned."
                        if snap.storage_classes
                        and c.storage_class
                        and c.storage_class not in {s.name for s in snap.storage_classes}
                        else "Check that the storage class exists and has capacity."
                    ),
                    evidence=[
                        Evidence(
                            source="pvc",
                            detail=f"{c.name}: Pending, class={c.storage_class or '(default)'}, size={c.requested}",
                        )
                    ],
                )
            )
        elif c.phase == "Lost":
            out.append(
                _finding(
                    comp,
                    f"pvc-lost-{c.name}",
                    f"{comp.label}: volume {c.name} is Lost",
                    Severity.CRITICAL,
                    "The underlying PersistentVolume is gone; data on this member is unavailable.",
                    evidence=[Evidence(source="pvc", detail=f"{c.name}: Lost")],
                )
            )
    ephemeral = False
    if comp.cr is not None and comp.cr.kind == "Kafka":
        storages = [np.spec.get("storage") or {} for np in comp.pools] or [
            (comp.cr.spec.get("kafka") or {}).get("storage") or {}
        ]

        def is_ephemeral(st: dict[str, Any]) -> bool:
            if st.get("type") == "jbod":
                vols = st.get("volumes") or []
                return bool(vols) and all(v.get("type") == "ephemeral" for v in vols)
            return st.get("type") == "ephemeral"

        ephemeral = any(is_ephemeral(st) for st in storages)
    elif comp.cr is None and comp.specs:
        has_pvc = any(
            s.volume_claim_templates or any(v.kind == "persistentVolumeClaim" for v in s.template_volumes)
            for s in comp.specs
        )
        ephemeral = not has_pvc
    if ephemeral:
        sev = Severity.MEDIUM if comp.kind == "redis" else Severity.HIGH
        out.append(
            _finding(
                comp,
                "ephemeral",
                f"{comp.label} stores data on ephemeral storage",
                sev,
                "No PersistentVolumeClaim backs the data directory: every pod restart or reschedule "
                "erases its data." + (" Acceptable only if Redis is a pure cache." if comp.kind == "redis" else ""),
                category="config",
            )
        )
    return out


def _check_pdb(snap: Snapshot, comp: Component) -> list[Finding]:
    if comp.desired < 2 or not comp.pods:
        return []
    covered = any(
        pdb.namespace == comp.namespace and selectors.matches(pdb.selector, comp.pods[0].labels) for pdb in snap.pdbs
    )
    if covered:
        return []
    sel = comp.pod_labels_selector
    hints = (
        [
            RemediationHint(
                kind="add-pdb",
                params={"selector": _sel_str(sel), "max_unavailable": "1", "name": f"{comp.name}-pdb"},
                summary="Add a PodDisruptionBudget allowing at most 1 member down at a time",
            )
        ]
        if sel
        else []
    )
    return [
        _finding(
            comp,
            "no-pdb",
            f"{comp.label} has no PodDisruptionBudget",
            Severity.MEDIUM,
            "Node drains and cluster upgrades may evict several members at once and break quorum or "
            "availability. A PDB with maxUnavailable: 1 makes voluntary disruptions one member at a time.",
            category="config",
            hints=hints,
        )
    ]


def _sel_str(sel: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(sel.items()))


def _check_spread(snap: Snapshot, comp: Component) -> list[Finding]:
    schedulable = [n for n in snap.nodes if n.ready and not any("NoSchedule" in t for t in n.taints)]
    placed = [p for p in comp.pods if p.node]
    if comp.desired < 2 or len(schedulable) < 2 or len(placed) < 2:
        return []
    by_node: dict[str, list[str]] = {}
    for p in placed:
        by_node.setdefault(p.node or "", []).append(p.name)
    crowded = {n: ps for n, ps in by_node.items() if len(ps) > 1}
    if not crowded:
        return []
    node, pods = max(crowded.items(), key=lambda kv: len(kv[1]))
    return [
        _finding(
            comp,
            "spread",
            f"{comp.label}: {len(pods)} members share node {node}",
            Severity.MEDIUM,
            f"Losing node {node} takes down {len(pods)} of {comp.desired} members at once. Add pod "
            "anti-affinity or topology spread constraints on kubernetes.io/hostname.",
            category="config",
            evidence=[Evidence(source="scheduling", detail=f"{n}: {', '.join(ps)}") for n, ps in crowded.items()],
        )
    ]


def _check_resources(comp: Component) -> list[Finding]:
    missing = [c.name for c in comp.containers if not c.resources.memory_limit]
    if comp.cr is not None and comp.cr.kind == "Kafka":
        if comp.pools:
            missing = [np.name for np in comp.pools if _limit_of(np.spec.get("resources")) is None]
        else:
            lim = (((comp.cr.spec.get("kafka") or {}).get("resources") or {}).get("limits") or {}).get("memory")
            missing = [] if lim else ["kafka"]
    if not missing:
        return []
    return [
        _finding(
            comp,
            "no-limit",
            f"{comp.label} has no memory limit",
            Severity.MEDIUM,
            "Without a memory limit the process can consume the node's memory and get other pods evicted; "
            "with JVM systems the heap and page cache can't be sized against a known budget.",
            category="config",
        )
    ]


def _exposed(comp: Component, ports: set[int]) -> list[ServiceInfo]:
    def hits(p: ServicePort) -> bool:
        target = p.target_port or ""
        return p.port in ports or (target.isdigit() and int(target) in ports)

    return [s for s in comp.services if s.external and any(hits(p) for p in s.ports)]


def _check_exposure(comp: Component, auth_disabled: bool) -> list[Finding]:
    out: list[Finding] = []
    client = _exposed(comp, CLIENT_PORTS.get(comp.kind, set()))
    if client:
        sev = Severity.CRITICAL if auth_disabled else Severity.HIGH
        out.append(
            _finding(
                comp,
                "exposed",
                f"{comp.label} is reachable from outside the cluster",
                sev,
                f"Service(s) {', '.join(s.name for s in client)} expose the {DISPLAY[comp.kind]} client "
                f"port through {'/'.join(sorted({s.type for s in client}))}."
                + (
                    " Authentication is disabled, so anyone who can reach it can read and change data."
                    if auth_disabled
                    else " Data stores should be reachable only from inside the cluster."
                ),
                category="security",
                evidence=[
                    Evidence(
                        source="service",
                        detail=f"{s.name}: type={s.type}, ports={','.join(str(p.port) for p in s.ports)}",
                    )
                    for s in client
                ],
                hints=[
                    RemediationHint(
                        kind="make-service-internal",
                        params={"services": ",".join(s.name for s in client)},
                        summary="Change the Service type to ClusterIP (or restrict loadBalancerSourceRanges)",
                    )
                ],
            )
        )
    admin = _exposed(comp, ADMIN_PORTS.get(comp.kind, set()))
    if admin:
        out.append(
            _finding(
                comp,
                "admin-exposed",
                f"{comp.label} admin/cluster port is exposed outside the cluster",
                Severity.HIGH,
                f"Service(s) {', '.join(s.name for s in admin)} expose a management or inter-node port externally.",
                category="security",
                hints=[
                    RemediationHint(
                        kind="make-service-internal",
                        params={"services": ",".join(s.name for s in admin)},
                        summary="Change the Service type to ClusterIP; reach the UI with kubectl port-forward",
                    )
                ],
            )
        )
    return out


def _check_netpol(snap: Snapshot, comp: Component, client_namespaces: set[str]) -> list[Finding]:
    if not comp.pods:
        return []
    if selectors.covering_policies(comp.pods[0], snap.network_policies, "Ingress"):
        return []
    sel = comp.pod_labels_selector
    from_ns = sorted(client_namespaces - {comp.namespace})
    hints = []
    if sel:
        hints.append(
            RemediationHint(
                kind="restrict-ingress",
                params={
                    "selector": _sel_str(sel),
                    "from_namespaces": ",".join(from_ns),
                    "name": f"{comp.name}-ingress",
                },
                summary="Allow ingress only from its own namespace"
                + (f" and known clients in {', '.join(from_ns)}" if from_ns else ""),
            )
        )
    return [
        _finding(
            comp,
            "no-netpol",
            f"{comp.label} accepts connections from any pod",
            Severity.MEDIUM,
            "No NetworkPolicy restricts ingress, so any compromised pod in the cluster can reach this data "
            "store directly.",
            category="security",
            hints=hints,
        )
    ]


_READY_TYPES = {"Ready", "ReconcileSuccess", "AllReplicasReady", "ClusterAvailable"}
_HEALTHY_PHASES = {"running", "ready", "cluster in healthy state", "healthy"}
# Phases that mean "failed", not "busy": Zalando *Failed/Invalid, ECK Invalid/Stalled, MongoDB Failed, OT Redis Failed.
_FAILED_PHASE_WORDS = ("fail", "invalid", "stalled", "error", "unable", "cannot")


def _check_operator_status(comp: Component) -> list[Finding]:
    cr = comp.cr
    if cr is None:
        return []
    out: list[Finding] = []
    bad = [
        c
        for c in cr.conditions
        if (c.type in _READY_TYPES and c.status == "False") or (c.type == "NotReady" and c.status == "True")
    ]
    phase = str(cr.status.get("phase") or cr.status.get("PostgresClusterStatus") or cr.status.get("state") or "")
    p_low = phase.strip().lower()
    phase_bad = bool(phase) and p_low not in _HEALTHY_PHASES
    failed = bool(bad) or any(w in p_low for w in _FAILED_PHASE_WORDS)
    if phase_bad and not failed:
        # Creating / Updating / ApplyingChanges / Pending / Initializing...: the operator is still working.
        out.append(
            _finding(
                comp,
                "operator-busy",
                f"{comp.label}: the {_OPERATOR_NAME.get(cr.group, 'operator')} is still reconciling "
                f"({clean(phase, 60)})",
                Severity.MEDIUM,
                "The operator is applying a change or creating members; this is normal during rollouts "
                "but a problem if it stays in this phase.",
                evidence=[Evidence(source="operator", detail=f"phase: {clean(phase, 120)}")],
            )
        )
    elif bad or phase_bad:
        ev = [
            Evidence(source="operator", detail=f"{c.type}={c.status} {c.reason or ''}: {clean(c.message, 240)}")
            for c in bad[:4]
        ]
        if phase_bad:
            ev.append(Evidence(source="operator", detail=f"phase: {clean(phase, 120)}"))
        out.append(
            _finding(
                comp,
                "operator",
                f"{comp.label}: the {_OPERATOR_NAME.get(cr.group, 'operator')} reports a problem",
                Severity.HIGH,
                "The operator managing this component says it is "
                "not healthy; its status message usually names the exact cause.",
                evidence=ev,
            )
        )
    health = str(cr.status.get("health") or "").lower()
    if health == "red":
        out.append(
            _finding(
                comp,
                "health-red",
                f"{comp.label}: cluster health is RED",
                Severity.CRITICAL,
                "At least one primary shard is unassigned: some data is unavailable and writes to those indices fail.",
            )
        )
    elif health == "yellow":
        out.append(
            _finding(
                comp,
                "health-yellow",
                f"{comp.label}: cluster health is YELLOW",
                Severity.MEDIUM,
                "All primary shards are assigned but some replicas are not: one more node failure can "
                "lose data availability.",
            )
        )
    return out


def _check_jvm(comp: Component) -> list[Finding]:
    if comp.kind not in JVM_KINDS:
        return []
    out: list[Finding] = []
    for sz in sizings(comp):
        out += _check_heap(comp, sz)
    return out


def _check_heap(comp: Component, sz: Sizing) -> list[Finding]:
    heap, limit = sz.heap, sz.limit
    if heap is None or limit is None:
        return []
    hs, ls = quantity.format_memory(heap), quantity.format_memory(limit)
    search = comp.kind in ("opensearch", "elasticsearch")
    raw = heap * 2 if search else math.ceil(heap / 0.75)
    step = 512 * 2**20 if raw > 2**30 else 128 * 2**20  # round up to a value humans would write
    target = math.ceil(raw / step) * step
    where = f" ({sz.scope})" if sz.scope else ""
    rule = "heap" + (f"-{sz.target.get('target_name')}" if sz.target else "")
    hint = RemediationHint(
        kind="set-memory-limit",
        params={
            "container": comp.containers[0].name if comp.containers else "",
            "current": ls,
            "proposed": quantity.format_memory(Decimal(target)),
            "jvm": "true",
            **sz.target,
        },
        summary=f"Raise the memory limit{where} to {quantity.format_memory(Decimal(target))} (or lower the heap)",
    )
    if heap >= limit:
        return [
            _finding(
                comp,
                rule,
                f"{comp.label}{where}: JVM heap ({hs}) is not smaller than the memory limit ({ls})",
                Severity.CRITICAL,
                "The heap alone fills the container's memory; with thread stacks, "
                "metaspace and direct buffers the kernel will OOM-kill the JVM under load.",
                category="config",
                hints=[hint],
            )
        ]
    if heap > 0.75 * limit:
        return [
            _finding(
                comp,
                rule,
                f"{comp.label}{where}: JVM heap ({hs}) leaves little headroom under the limit ({ls})",
                Severity.HIGH,
                "JVM off-heap memory needs roughly 25% of the limit; above 75% heap the "
                "container is likely to be OOM-killed.",
                category="config",
                hints=[hint],
            )
        ]
    if search and heap > 0.5 * limit:
        return [
            _finding(
                comp,
                rule,
                f"{comp.label}{where}: heap ({hs}) is more than half the memory limit ({ls})",
                Severity.MEDIUM,
                f"{DISPLAY[comp.kind]} relies on the OS page cache for Lucene segments; "
                "the recommended heap is at most 50% of available memory.",
                category="config",
                hints=[hint],
            )
        ]
    return []


def _check_kafka(comp: Component) -> list[Finding]:
    if comp.kind != "kafka":
        return []
    cfg = kafka_config(comp)
    brokers = comp.brokers_desired
    ready = comp.brokers_ready
    out: list[Finding] = []

    def num(key: str) -> int | None:
        v = cfg.get(key)
        return int(v) if v is not None and str(v).strip().isdigit() else None

    rf, isr, off_rf = (
        num("default.replication.factor"),
        num("min.insync.replicas"),
        num("offsets.topic.replication.factor"),
    )
    if rf is not None and brokers and rf > brokers:
        out.append(
            _finding(
                comp,
                "rf-gt-brokers",
                f"{comp.label}: replication factor {rf} exceeds broker count {brokers}",
                Severity.CRITICAL,
                "New topics cannot be created until enough brokers exist.",
                category="config",
            )
        )
    if rf is not None and isr is not None and isr >= rf and rf > 1:
        sev = Severity.CRITICAL if ready < isr else Severity.HIGH
        out.append(
            _finding(
                comp,
                "isr",
                f"{comp.label}: min.insync.replicas ({isr}) leaves no room for a broker "
                f"failure (replication factor {rf})",
                sev,
                "Producers using acks=all fail as soon as one replica is unavailable (rolling restarts "
                "included). Use min.insync.replicas = replication factor - 1 (typically RF 3, ISR 2)."
                + (
                    f" Right now only {ready} brokers are ready, so writes are already failing with NotEnoughReplicas."
                    if ready < isr
                    else ""
                ),
                category="config",
                hints=[
                    RemediationHint(
                        kind="set-kafka-config",
                        params={"key": "min.insync.replicas", "current": str(isr), "proposed": str(rf - 1)},
                        summary=f"Set min.insync.replicas to {rf - 1} in the Kafka resource",
                    )
                ]
                if comp.cr is not None and comp.cr.kind == "Kafka"
                else [],
            )
        )
    elif isr is not None and ready < isr <= brokers:
        out.append(
            _finding(
                comp,
                "isr-down",
                f"{comp.label}: fewer brokers ready ({ready}) than min.insync.replicas ({isr})",
                Severity.CRITICAL,
                "Writes with acks=all are rejected (NotEnoughReplicas) until more brokers recover.",
            )
        )
    if rf == 1 and brokers > 1:
        out.append(
            _finding(
                comp,
                "rf1",
                f"{comp.label}: default replication factor is 1",
                Severity.MEDIUM,
                "Each partition lives on one broker; losing that broker loses its data.",
                category="config",
            )
        )
    if off_rf is not None and off_rf < 3 <= brokers:
        out.append(
            _finding(
                comp,
                "offsets-rf",
                f"{comp.label}: consumer offsets topic replication factor is {off_rf}",
                Severity.MEDIUM,
                "Consumer group offsets can be lost or become unavailable when a broker fails.",
                category="config",
            )
        )
    if comp.cr is not None:
        for lst in (comp.cr.spec.get("kafka") or {}).get("listeners") or []:
            if (
                lst.get("type") in ("loadbalancer", "nodeport", "route", "ingress")
                and not lst.get("tls")
                and not lst.get("authentication")
            ):
                out.append(
                    _finding(
                        comp,
                        f"listener-{lst.get('name')}",
                        f"{comp.label}: external listener '{lst.get('name')}' is plaintext and unauthenticated",
                        Severity.HIGH,
                        "Anyone who can reach the external address can produce and consume any topic, "
                        "in clear text. Enable TLS and authentication (scram-sha-512 or tls).",
                        category="security",
                    )
                )
    return out


def _search_security_disabled(comp: Component) -> bool:
    if comp.kind not in ("opensearch", "elasticsearch"):
        return False
    if _truthy(env_value(comp, "DISABLE_SECURITY_PLUGIN")):
        return True
    for c in comp.containers:
        for e in c.env:
            n = e.name.lower().replace("_", ".")
            if n in ("plugins.security.disabled",) and _truthy(e.value):
                return True
            if n in ("xpack.security.enabled",) and e.value is not None and e.value.strip().lower() == "false":
                return True
    return any("plugins.security.disabled=true" in a or "xpack.security.enabled=false" in a for a in _all_args(comp))


def _check_search(comp: Component) -> list[Finding]:
    if comp.kind not in ("opensearch", "elasticsearch"):
        return []
    out: list[Finding] = []
    if _search_security_disabled(comp):
        out.append(
            _finding(
                comp,
                "security-off",
                f"{comp.label} runs with its security plugin disabled",
                Severity.HIGH,
                "No authentication, authorization or TLS: any client that can connect "
                "can read, change or delete every index.",
                category="security",
            )
        )
    single = env_value(comp, "discovery.type", "DISCOVERY_TYPE")
    if single and single.strip() == "single-node" and comp.desired > 1:
        out.append(
            _finding(
                comp,
                "single-node-discovery",
                f"{comp.label}: discovery.type=single-node with {comp.desired} replicas",
                Severity.HIGH,
                "Each pod forms its own one-node cluster "
                "instead of joining the others: data is split and inconsistent.",
                category="config",
            )
        )
    return out


def _redis_no_auth(comp: Component) -> bool:
    if comp.kind != "redis":
        return False
    if _truthy(env_value(comp, "ALLOW_EMPTY_PASSWORD")):
        return True
    args = " ".join(_all_args(comp))
    return "--protected-mode no" in args


def _postgres_trust(comp: Component) -> bool:
    return comp.kind == "postgresql" and (env_value(comp, "POSTGRES_HOST_AUTH_METHOD") or "").strip() == "trust"


def _mongo_no_auth(comp: Component) -> bool:
    if comp.kind != "mongodb" or comp.cr is not None:
        return False
    args = " ".join(_all_args(comp))
    open_bind = "--bind_ip_all" in args or "--bind_ip 0.0.0.0" in args
    return (
        open_bind
        and "--auth" not in args
        and env_value(comp, "MONGO_INITDB_ROOT_USERNAME") is None
        and not any(e.name == "MONGO_INITDB_ROOT_USERNAME" for c in comp.containers for e in c.env)
    )


def _check_auth(comp: Component) -> list[Finding]:
    if _redis_no_auth(comp):
        return [
            _finding(
                comp,
                "auth-off",
                f"{comp.label} accepts connections without a password",
                Severity.HIGH,
                "ALLOW_EMPTY_PASSWORD / protected-mode off: any pod that can reach it can read and overwrite "
                "all keys, or use CONFIG to write files.",
                category="security",
            )
        ]
    if _postgres_trust(comp):
        return [
            _finding(
                comp,
                "auth-off",
                f"{comp.label} trusts every connection (POSTGRES_HOST_AUTH_METHOD=trust)",
                Severity.CRITICAL,
                "Any client can log in as any user, including the superuser, without a password.",
                category="security",
            )
        ]
    if _mongo_no_auth(comp):
        return [
            _finding(
                comp,
                "auth-off",
                f"{comp.label} listens on all interfaces without authentication",
                Severity.HIGH,
                "Started with --bind_ip_all and no --auth or root user: anyone who can reach it has full access.",
                category="security",
            )
        ]
    return []


def _check_postgres(comp: Component) -> list[Finding]:
    if comp.kind != "postgresql" or comp.cr is not None:
        return []
    multi = [s for s in comp.specs if s.kind == "Deployment" and s.replicas > 1]
    if multi:
        return [
            _finding(
                comp,
                "pg-multi-writer",
                f"{comp.label}: {multi[0].replicas} PostgreSQL replicas in one Deployment",
                Severity.CRITICAL,
                "A Deployment's replicas are identical primaries; if they "
                "share a volume they corrupt the data directory, and if they don't, each holds different "
                "data. Use a StatefulSet with replication or an operator (CloudNativePG).",
                category="config",
            )
        ]
    return []


def auth_disabled(comp: Component) -> bool:
    return _search_security_disabled(comp) or _redis_no_auth(comp) or _postgres_trust(comp) or _mongo_no_auth(comp)


def diagnose_component(
    snap: Snapshot,
    comp: Component,
    client_namespaces: set[str] | None = None,
    all_components: list[Component] | None = None,
) -> list[Finding]:
    if comp.layer != "data":
        return _diagnose_platform(snap, comp, all_components or [comp])
    findings: list[Finding] = []
    findings += _check_availability(comp)
    findings += _check_quorum(comp)
    findings += _check_operator_status(comp)
    findings += _check_storage(snap, comp)
    findings += _check_kafka(comp)
    findings += _check_jvm(comp)
    findings += _check_search(comp)
    findings += _check_auth(comp)
    findings += _check_postgres(comp)
    findings += _check_exposure(comp, auth_disabled(comp))
    findings += _check_single(comp)
    findings += _check_pdb(snap, comp)
    findings += _check_spread(snap, comp)
    findings += _check_resources(comp)
    findings += _check_netpol(snap, comp, client_namespaces or set())
    return sorted(findings, key=lambda f: -f.severity)


def _diagnose_platform(snap: Snapshot, comp: Component, comps: list[Component]) -> list[Finding]:
    findings = _check_availability(comp)
    daemon = any(s.kind == "DaemonSet" for s in comp.specs)
    if comp.layer == "edge":
        findings += layers.check_ingress_nginx(snap, comp, comps) if comp.kind == "ingress-nginx" else []
        findings += layers.check_kong(snap, comp, comps) if comp.kind == "kong" else []
        if not daemon:
            findings += _check_single(comp)
            findings += _check_pdb(snap, comp)
            findings += _check_spread(snap, comp)
    elif comp.layer == "logging":
        findings += layers.check_logging(snap, comp)
    findings += layers.check_service_component(snap, comp)
    impact = layers.IMPACT.get(comp.kind)
    if impact is not None:
        sev, text = impact
        findings = [
            f.model_copy(
                update={
                    "severity": max(f.severity, sev) if " is down (0/" in f.title else f.severity,
                    "explanation": f"{f.explanation} {text}",
                }
            )
            if (" is down (0/" in f.title or " is degraded (" in f.title)
            else f
            for f in findings
        ]
    if comp.layer in ("edge", "logging"):
        findings += _check_resources(comp)
    # an "edge-down" finding already says it all: drop the generic "down" duplicate
    if any(f.title.endswith("unreachable from outside") for f in findings):
        findings = [f for f in findings if " is down (0/" not in f.title]
    return sorted(findings, key=lambda f: -f.severity)


def status_of(findings: list[Finding]) -> str:
    """down | critical | degraded (availability, from reliability findings) | at-risk (serving, but high/critical
    security or config issues) | healthy."""
    rel = [f for f in findings if f.category == "reliability"]
    if any(" is down" in f.title or "lost quorum" in f.title for f in rel):
        return "down"
    if any(f.severity == Severity.CRITICAL for f in rel):
        return "critical"
    if any(f.severity >= Severity.HIGH for f in rel):
        return "degraded"
    if any(f.severity >= Severity.HIGH for f in findings):
        return "at-risk"
    return "healthy"


def selector_of(comp: Component) -> LabelSelector:
    return LabelSelector(match_labels=comp.pod_labels_selector)
