"""Convert raw Kubernetes objects (API JSON shape, camelCase) into normalized models.

Both the live backend (via ``ApiClient.sanitize_for_serialization``) and the fixture backend
produce the same raw dict shape, so all parsing lives here and is covered by fixture tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from kubepilot.models import (
    BindingInfo,
    Container,
    ContainerState,
    Event,
    FalcoAlert,
    LabelSelector,
    NetworkPolicyInfo,
    Node,
    Pod,
    PolicyRule,
    ReplicaSetInfo,
    Resources,
    RoleInfo,
    SecurityContext,
    Severity,
    Subject,
    Volume,
    Vulnerability,
    VulnerabilityReport,
    WorkloadRef,
)

Raw = dict[str, Any]

# Kinds whose pods are owned through an intermediate ReplicaSet / Job.
_TOP_LEVEL_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "ReplicaSet"}


def ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value).replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _meta(obj: Raw) -> Raw:
    m = obj.get("metadata") or {}
    return m if isinstance(m, dict) else {}


def _controller_ref(obj: Raw) -> Raw | None:
    refs = _meta(obj).get("ownerReferences") or []
    for r in refs:
        if r.get("controller"):
            return dict(r)
    return dict(refs[0]) if refs else None


# ---------------------------------------------------------------- ownership


class OwnerIndex:
    """Resolves ReplicaSet → Deployment and Job → CronJob chains."""

    def __init__(self, replicasets: list[Raw], jobs: list[Raw] | None = None) -> None:
        self._rs: dict[tuple[str, str], Raw] = {}
        for rs in replicasets:
            m = _meta(rs)
            self._rs[(m.get("namespace", ""), m.get("name", ""))] = rs
        self._jobs: dict[tuple[str, str], Raw] = {}
        for job in jobs or []:
            m = _meta(job)
            self._jobs[(m.get("namespace", ""), m.get("name", ""))] = job

    def top_level(self, namespace: str, kind: str, name: str) -> WorkloadRef:
        if kind == "ReplicaSet":
            rs = self._rs.get((namespace, name))
            ref = _controller_ref(rs) if rs else None
            if ref and ref.get("kind") == "Deployment":
                return WorkloadRef(kind="Deployment", namespace=namespace, name=ref["name"])
        if kind == "Job":
            job = self._jobs.get((namespace, name))
            ref = _controller_ref(job) if job else None
            if ref and ref.get("kind") == "CronJob":
                return WorkloadRef(kind="CronJob", namespace=namespace, name=ref["name"])
        return WorkloadRef(kind=kind, namespace=namespace, name=name)


# ---------------------------------------------------------------- containers


def _state(raw: Raw | None) -> ContainerState:
    if not raw:
        return ContainerState()
    for key in ("waiting", "running", "terminated"):
        if raw.get(key) is not None:
            s = raw[key] or {}
            return ContainerState(
                state=key,
                reason=s.get("reason"),
                message=s.get("message"),
                exit_code=s.get("exitCode"),
                started_at=ts(s.get("startedAt")),
                finished_at=ts(s.get("finishedAt")),
            )
    return ContainerState()


def _security(pod_sc: Raw | None, c_sc: Raw | None) -> SecurityContext:
    pod_sc = pod_sc or {}
    c_sc = c_sc or {}

    def pick(key: str) -> Any:
        return c_sc[key] if c_sc.get(key) is not None else pod_sc.get(key)

    caps = c_sc.get("capabilities") or {}
    return SecurityContext(
        privileged=bool(c_sc.get("privileged", False)),
        run_as_non_root=pick("runAsNonRoot"),
        run_as_user=pick("runAsUser"),
        allow_privilege_escalation=c_sc.get("allowPrivilegeEscalation"),
        read_only_root_filesystem=c_sc.get("readOnlyRootFilesystem"),
        capabilities_add=[str(x) for x in caps.get("add") or []],
        capabilities_drop=[str(x) for x in caps.get("drop") or []],
    )


def _resources(raw: Raw | None) -> Resources:
    raw = raw or {}
    req = raw.get("requests") or {}
    lim = raw.get("limits") or {}
    return Resources(
        cpu_request=_s(req.get("cpu")),
        cpu_limit=_s(lim.get("cpu")),
        memory_request=_s(req.get("memory")),
        memory_limit=_s(lim.get("memory")),
    )


def _s(v: Any) -> str | None:
    return None if v is None else str(v)


def containers_from_spec(spec: Raw, statuses: Raw | None = None) -> list[Container]:
    statuses = statuses or {}
    by_name: dict[str, Raw] = {}
    for st in (statuses.get("containerStatuses") or []) + (statuses.get("initContainerStatuses") or []):
        by_name[st.get("name", "")] = st
    pod_sc = spec.get("securityContext")
    out: list[Container] = []
    for init, key in ((True, "initContainers"), (False, "containers")):
        for c in spec.get(key) or []:
            st = by_name.get(c.get("name", ""), {})
            out.append(
                Container(
                    name=c.get("name", ""),
                    image=c.get("image", ""),
                    init=init,
                    resources=_resources(c.get("resources")),
                    security=_security(pod_sc, c.get("securityContext")),
                    has_liveness_probe=c.get("livenessProbe") is not None,
                    has_readiness_probe=c.get("readinessProbe") is not None,
                    ready=bool(st.get("ready", False)),
                    restart_count=int(st.get("restartCount", 0) or 0),
                    state=_state(st.get("state")),
                    last_state=_state(st.get("lastState")),
                    image_id=st.get("imageID"),
                )
            )
    return out


def _volumes(spec: Raw) -> list[Volume]:
    out: list[Volume] = []
    for v in spec.get("volumes") or []:
        name = v.get("name", "")
        kind, source = "other", None
        if "hostPath" in v:
            kind, source = "hostPath", (v["hostPath"] or {}).get("path")
        elif "secret" in v:
            kind, source = "secret", (v["secret"] or {}).get("secretName")
        elif "configMap" in v:
            kind, source = "configMap", (v["configMap"] or {}).get("name")
        elif "persistentVolumeClaim" in v:
            kind, source = "persistentVolumeClaim", (v["persistentVolumeClaim"] or {}).get("claimName")
        elif "emptyDir" in v:
            kind = "emptyDir"
        elif "projected" in v:
            kind = "projected"
        out.append(Volume(name=name, kind=kind, source=source))
    return out


# ---------------------------------------------------------------- top-level objects


def pod(raw: Raw, owners: OwnerIndex) -> Pod:
    m = _meta(raw)
    spec = raw.get("spec") or {}
    status = raw.get("status") or {}
    ns = m.get("namespace", "default")
    ref = _controller_ref(raw)
    owner: WorkloadRef | None = None
    replicaset: str | None = None
    if ref and ref.get("kind") in _TOP_LEVEL_KINDS:
        if ref["kind"] == "ReplicaSet":
            replicaset = ref["name"]
        owner = owners.top_level(ns, ref["kind"], ref["name"])
    conditions: dict[str, str] = {}
    unsched: str | None = None
    for cond in status.get("conditions") or []:
        conditions[cond.get("type", "")] = cond.get("status", "")
        if cond.get("type") == "PodScheduled" and cond.get("reason") == "Unschedulable":
            unsched = cond.get("message")
    return Pod(
        namespace=ns,
        name=m.get("name", ""),
        uid=m.get("uid", ""),
        labels=dict(m.get("labels") or {}),
        phase=status.get("phase", "Unknown"),
        node=spec.get("nodeName"),
        service_account=spec.get("serviceAccountName") or "default",
        automount_sa_token=spec.get("automountServiceAccountToken", True) is not False,
        host_network=bool(spec.get("hostNetwork", False)),
        host_pid=bool(spec.get("hostPID", False)),
        host_ipc=bool(spec.get("hostIPC", False)),
        containers=containers_from_spec(spec, status),
        volumes=_volumes(spec),
        owner=owner,
        replicaset=replicaset,
        created_at=ts(m.get("creationTimestamp")),
        conditions=conditions,
        unschedulable_message=unsched,
    )


def replicaset(raw: Raw, owners: OwnerIndex) -> ReplicaSetInfo:
    m = _meta(raw)
    ns = m.get("namespace", "default")
    ref = _controller_ref(raw)
    owner = owners.top_level(ns, ref["kind"], ref["name"]) if ref else None
    rev = (m.get("annotations") or {}).get("deployment.kubernetes.io/revision")
    tmpl_spec = ((raw.get("spec") or {}).get("template") or {}).get("spec") or {}
    return ReplicaSetInfo(
        namespace=ns,
        name=m.get("name", ""),
        owner=owner,
        revision=int(rev) if rev and str(rev).isdigit() else None,
        created_at=ts(m.get("creationTimestamp")),
        replicas=int((raw.get("spec") or {}).get("replicas") or 0),
        containers=containers_from_spec(tmpl_spec),
    )


def event(raw: Raw) -> Event:
    m = _meta(raw)
    io = raw.get("involvedObject") or raw.get("regarding") or {}
    series = raw.get("series") or {}
    return Event(
        namespace=m.get("namespace") or io.get("namespace", ""),
        involved_kind=io.get("kind", ""),
        involved_name=io.get("name", ""),
        type=raw.get("type", "Normal"),
        reason=raw.get("reason", ""),
        message=raw.get("message") or raw.get("note") or "",
        count=int(raw.get("count") or series.get("count") or 1),
        first_seen=ts(raw.get("firstTimestamp") or raw.get("eventTime") or m.get("creationTimestamp")),
        last_seen=ts(
            raw.get("lastTimestamp")
            or series.get("lastObservedTime")
            or raw.get("eventTime")
            or m.get("creationTimestamp")
        ),
    )


def node(raw: Raw) -> Node:
    m = _meta(raw)
    status = raw.get("status") or {}
    conds = {c.get("type", ""): c.get("status", "") for c in status.get("conditions") or []}
    alloc = status.get("allocatable") or {}
    taints = [
        f"{t.get('key')}={t.get('value', '')}:{t.get('effect')}" for t in (raw.get("spec") or {}).get("taints") or []
    ]
    return Node(
        name=m.get("name", ""),
        ready=conds.get("Ready") == "True",
        conditions=conds,
        allocatable_cpu=_s(alloc.get("cpu")),
        allocatable_memory=_s(alloc.get("memory")),
        taints=taints,
    )


def selector(raw: Raw | None) -> LabelSelector:
    raw = raw or {}
    return LabelSelector(
        match_labels=dict(raw.get("matchLabels") or {}),
        match_expressions=list(raw.get("matchExpressions") or []),
    )


def network_policy(raw: Raw) -> NetworkPolicyInfo:
    m = _meta(raw)
    spec = raw.get("spec") or {}
    types = list(spec.get("policyTypes") or [])
    if not types:  # API defaulting: Ingress always, Egress if egress rules present
        types = ["Ingress"] + (["Egress"] if spec.get("egress") else [])
    return NetworkPolicyInfo(
        namespace=m.get("namespace", "default"),
        name=m.get("name", ""),
        pod_selector=selector(spec.get("podSelector")),
        policy_types=types,
    )


def role(raw: Raw) -> RoleInfo:
    m = _meta(raw)
    kind = raw.get("kind", "Role")
    rules = [
        PolicyRule(
            api_groups=list(r.get("apiGroups") or []),
            resources=list(r.get("resources") or []),
            verbs=list(r.get("verbs") or []),
            resource_names=list(r.get("resourceNames") or []),
        )
        for r in raw.get("rules") or []
    ]
    return RoleInfo(
        kind="ClusterRole" if kind == "ClusterRole" else "Role",
        namespace=None if kind == "ClusterRole" else m.get("namespace"),
        name=m.get("name", ""),
        rules=rules,
    )


def binding(raw: Raw) -> BindingInfo:
    m = _meta(raw)
    kind = raw.get("kind", "RoleBinding")
    ref = raw.get("roleRef") or {}
    return BindingInfo(
        kind="ClusterRoleBinding" if kind == "ClusterRoleBinding" else "RoleBinding",
        namespace=None if kind == "ClusterRoleBinding" else m.get("namespace"),
        name=m.get("name", ""),
        role_kind="ClusterRole" if ref.get("kind") == "ClusterRole" else "Role",
        role_name=ref.get("name", ""),
        subjects=[
            Subject(kind=s.get("kind", ""), name=s.get("name", ""), namespace=s.get("namespace"))
            for s in raw.get("subjects") or []
        ],
    )


_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def vulnerability_report(raw: Raw, owners: OwnerIndex) -> VulnerabilityReport:
    """Trivy Operator ``VulnerabilityReport`` (aquasecurity.github.io/v1alpha1)."""
    m = _meta(raw)
    labels = m.get("labels") or {}
    ns = labels.get("trivy-operator.resource.namespace") or m.get("namespace", "default")
    kind = labels.get("trivy-operator.resource.kind")
    name = labels.get("trivy-operator.resource.name")
    workload = owners.top_level(ns, kind, name) if kind and name else None
    report = raw.get("report") or {}
    art = report.get("artifact") or {}
    reg = (report.get("registry") or {}).get("server")
    image = art.get("repository", "")
    if reg and reg not in ("index.docker.io", "docker.io"):
        image = f"{reg}/{image}"
    if art.get("tag"):
        image = f"{image}:{art['tag']}"
    vulns = [
        Vulnerability(
            id=v.get("vulnerabilityID", ""),
            severity=_SEV.get(str(v.get("severity", "UNKNOWN")).upper(), Severity.INFO),
            package=v.get("resource", ""),
            installed_version=v.get("installedVersion", ""),
            fixed_version=v.get("fixedVersion") or None,
            title=v.get("title", ""),
            score=v.get("score"),
        )
        for v in report.get("vulnerabilities") or []
    ]
    return VulnerabilityReport(
        namespace=ns,
        workload=workload,
        container=labels.get("trivy-operator.container.name", ""),
        image=image,
        vulnerabilities=vulns,
    )


def falco_alert(raw: Raw) -> FalcoAlert:
    """Falco JSON output as forwarded by Falcosidekick's webhook output."""
    f = raw.get("output_fields") or raw.get("outputFields") or {}
    repo = f.get("container.image.repository")
    tag = f.get("container.image.tag")
    image = f"{repo}:{tag}" if repo and tag else repo
    return FalcoAlert(
        time=ts(raw.get("time")) or datetime.now(UTC),
        rule=str(raw.get("rule", "")),
        priority=str(raw.get("priority", "Notice")),
        output=str(raw.get("output", "")),
        namespace=f.get("k8s.ns.name"),
        pod=f.get("k8s.pod.name"),
        container=f.get("container.name"),
        image=image,
        tags=[str(t) for t in raw.get("tags") or []],
    )
