"""Live backend using the official Kubernetes Python client. Strictly read-only: list calls, plus
SelfSubjectAccessReviews (which change nothing) to warn about over-privileged credentials.

Required RBAC is shipped in ``deploy/rbac.yaml``. Secrets are never read.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from kubepilot.source.alerts import AlertStore
from kubepilot.source.base import LOG_LIMIT_BYTES, LOG_TAIL_LINES, RawCluster, Snapshot
from kubepilot.source.crds import OPERATOR_CRDS, PLATFORM_IMAGES

log = logging.getLogger(__name__)

TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
PAGE_SIZE = 500


class KubeSource:
    name = "kube"

    def __init__(
        self,
        context: str | None = None,
        alerts: AlertStore | None = None,
        falco_window: timedelta = timedelta(hours=24),
        cache_ttl: float = 10.0,
    ) -> None:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config(context=context)
        self._api = client.ApiClient()
        self._core = client.CoreV1Api(self._api)
        self._apps = client.AppsV1Api(self._api)
        self._batch = client.BatchV1Api(self._api)
        self._net = client.NetworkingV1Api(self._api)
        self._rbac = client.RbacAuthorizationV1Api(self._api)
        self._custom = client.CustomObjectsApi(self._api)
        self._policy = client.PolicyV1Api(self._api)
        self._alerts = alerts
        self._falco_window = falco_window
        self._cache_ttl = cache_ttl
        self._cache: dict[str | None, tuple[float, Snapshot]] = {}
        self._authz = client.AuthorizationV1Api(self._api)
        self._privilege_warnings: list[str] | None = None

    # ------------------------------------------------------------ credential hygiene

    # (verb, group, resource): things a read-only diagnosis tool should NOT be able to do.
    _RISKY_ACCESS = (
        ("get", "", "secrets"),
        ("create", "", "pods"),
        ("delete", "apps", "deployments"),
        ("create", "", "pods/exec"),
    )

    def privilege_warnings(self) -> list[str]:
        """Warn when kubepilot runs with credentials that can do more than read (it never uses them)."""
        if self._privilege_warnings is not None:
            return self._privilege_warnings
        from kubernetes import client

        allowed: list[str] = []
        for verb, group, resource in self._RISKY_ACCESS:
            sub_res = None
            if "/" in resource:
                resource, sub_res = resource.split("/", 1)
            body = client.V1SelfSubjectAccessReview(
                spec=client.V1SelfSubjectAccessReviewSpec(
                    resource_attributes=client.V1ResourceAttributes(
                        verb=verb, group=group, resource=resource, subresource=sub_res
                    )
                )
            )
            try:
                resp = self._authz.create_self_subject_access_review(body)
            except Exception as e:
                log.debug("access review failed: %s", e)
                continue
            if resp.status and resp.status.allowed:
                allowed.append(f"{verb} {resource}{'/' + sub_res if sub_res else ''}")
        self._privilege_warnings = (
            [
                "kubepilot is using credentials that can "
                + ", ".join(allowed)
                + ". It only ever reads, but use a read-only identity (deploy/rbac.yaml) to limit damage "
                "if the host or MCP client is compromised."
            ]
            if allowed
            else []
        )
        return self._privilege_warnings

    # ------------------------------------------------------------ helpers

    def _to_dicts(self, items: list[Any], kind: str) -> list[dict[str, Any]]:
        out = []
        for item in items:
            d = self._api.sanitize_for_serialization(item)
            d["kind"] = kind  # list responses omit kind on items
            out.append(d)
        return out

    def _list(self, fn: Callable[..., Any], kind: str, **kw: Any) -> list[dict[str, Any]]:
        items: list[Any] = []
        cont: str | None = None
        while True:
            resp = fn(limit=PAGE_SIZE, _continue=cont, **kw) if cont else fn(limit=PAGE_SIZE, **kw)
            items.extend(resp.items or [])
            cont = resp.metadata._continue if resp.metadata else None
            if not cont:
                return self._to_dicts(items, kind)

    def _scoped(
        self, ns: str | None, all_fn: Callable[..., Any], ns_fn: Callable[..., Any], kind: str
    ) -> list[dict[str, Any]]:
        if ns:
            return self._list(ns_fn, kind, namespace=ns)
        return self._list(all_fn, kind)

    def _trivy(self, ns: str | None, warnings: list[str]) -> list[dict[str, Any]]:
        from kubernetes.client.exceptions import ApiException

        try:
            if ns:
                resp = self._custom.list_namespaced_custom_object(
                    TRIVY_GROUP, TRIVY_VERSION, ns, "vulnerabilityreports"
                )
            else:
                resp = self._custom.list_cluster_custom_object(TRIVY_GROUP, TRIVY_VERSION, "vulnerabilityreports")
        except ApiException as e:
            if e.status in (403, 404):
                warnings.append(f"Trivy VulnerabilityReports unavailable (HTTP {e.status}); CVE signals skipped")
                return []
            raise
        items: list[dict[str, Any]] = cast(dict[str, Any], resp).get("items", [])
        for i in items:
            i["kind"] = "VulnerabilityReport"
        return list(items)

    def _operator_crs(self, ns: str | None) -> list[dict[str, Any]]:
        """List known operator CRs; CRDs that aren't installed (404) or not permitted (403) are skipped."""
        from kubernetes.client.exceptions import ApiException

        out: list[dict[str, Any]] = []
        for group, versions, plural, kind in OPERATOR_CRDS:
            for version in versions:
                try:
                    if ns:
                        resp = self._custom.list_namespaced_custom_object(group, version, ns, plural)
                    else:
                        resp = self._custom.list_cluster_custom_object(group, version, plural)
                except ApiException as e:
                    if e.status in (403, 404):
                        continue  # not installed / version not served / not allowed: try the next version
                    raise
                for item in cast(dict[str, Any], resp).get("items", []):
                    item.setdefault("kind", kind)
                    item.setdefault("apiVersion", f"{group}/{version}")
                    out.append(item)
                break  # first served version wins
        return out

    # ------------------------------------------------------------ API

    def _fetch_raw(self, ns: str | None, warnings: list[str]) -> RawCluster:
        core, apps, batch, net, rbac = self._core, self._apps, self._batch, self._net, self._rbac
        return RawCluster(
            pods=self._scoped(ns, core.list_pod_for_all_namespaces, core.list_namespaced_pod, "Pod"),
            replicasets=self._scoped(
                ns, apps.list_replica_set_for_all_namespaces, apps.list_namespaced_replica_set, "ReplicaSet"
            ),
            jobs=self._scoped(ns, batch.list_job_for_all_namespaces, batch.list_namespaced_job, "Job"),
            events=self._scoped(ns, core.list_event_for_all_namespaces, core.list_namespaced_event, "Event"),
            nodes=self._list(core.list_node, "Node"),
            network_policies=self._scoped(
                ns,
                net.list_network_policy_for_all_namespaces,
                net.list_namespaced_network_policy,
                "NetworkPolicy",
            ),
            roles=self._scoped(ns, rbac.list_role_for_all_namespaces, rbac.list_namespaced_role, "Role")
            + self._list(rbac.list_cluster_role, "ClusterRole"),
            bindings=self._scoped(
                ns,
                rbac.list_role_binding_for_all_namespaces,
                rbac.list_namespaced_role_binding,
                "RoleBinding",
            )
            + self._list(rbac.list_cluster_role_binding, "ClusterRoleBinding"),
            vulnerability_reports=self._trivy(ns, warnings),
            workloads=self._scoped(
                ns, apps.list_deployment_for_all_namespaces, apps.list_namespaced_deployment, "Deployment"
            )
            + self._scoped(
                ns, apps.list_stateful_set_for_all_namespaces, apps.list_namespaced_stateful_set, "StatefulSet"
            )
            + self._scoped(ns, apps.list_daemon_set_for_all_namespaces, apps.list_namespaced_daemon_set, "DaemonSet"),
            pvcs=self._scoped(
                ns,
                core.list_persistent_volume_claim_for_all_namespaces,
                core.list_namespaced_persistent_volume_claim,
                "PersistentVolumeClaim",
            ),
            services=self._scoped(ns, core.list_service_for_all_namespaces, core.list_namespaced_service, "Service"),
            pdbs=self._scoped(
                ns,
                self._policy.list_pod_disruption_budget_for_all_namespaces,
                self._policy.list_namespaced_pod_disruption_budget,
                "PodDisruptionBudget",
            ),
            custom_resources=self._operator_crs(ns),
            ingresses=self._scoped(ns, net.list_ingress_for_all_namespaces, net.list_namespaced_ingress, "Ingress"),
            ingress_classes=self._optional(lambda: self._list(net.list_ingress_class, "IngressClass")),
        )

    def _optional(self, fn: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
        from kubernetes.client.exceptions import ApiException

        try:
            return fn()
        except ApiException as e:
            if e.status in (403, 404):
                return []
            raise

    def _platform_config_maps(self, raw: RawCluster, warnings: list[str]) -> list[dict[str, Any]]:
        """ConfigMaps mounted by (or passed via --configmap to) platform pods: Fluent Bit, ingress-nginx, Kong.

        Fetched one by one by name, so nothing unrelated is read. Needs the optional `kubepilot-config` role."""
        from kubernetes.client.exceptions import ApiException

        wanted: set[tuple[str, str]] = set()
        for p in raw.pods:
            spec = p.get("spec") or {}
            ns = (p.get("metadata") or {}).get("namespace", "default")
            containers = spec.get("containers") or []
            if not any(PLATFORM_IMAGES.search(str(c.get("image", ""))) for c in containers):
                continue
            for v in spec.get("volumes") or []:
                if (v.get("configMap") or {}).get("name"):
                    wanted.add((ns, v["configMap"]["name"]))
            for c in containers:
                for arg in [*(c.get("args") or []), *(c.get("command") or [])]:
                    if str(arg).startswith("--configmap="):
                        ref = str(arg).split("=", 1)[1].replace("$(POD_NAMESPACE)", ns)
                        cns, _, cname = ref.rpartition("/")
                        wanted.add((cns or ns, cname))
        out: list[dict[str, Any]] = []
        for ns, name in sorted(wanted)[:50]:
            try:
                cm = self._core.read_namespaced_config_map(name, ns)
            except ApiException as e:
                if e.status == 403:
                    warnings.append(
                        "Cannot read platform ConfigMaps (Fluent Bit / ingress-nginx config checks skipped); "
                        "apply the optional kubepilot-config ClusterRole in deploy/rbac.yaml"
                    )
                    return out
                if e.status == 404:
                    continue
                raise
            d = self._api.sanitize_for_serialization(cm)
            d["kind"] = "ConfigMap"
            out.append(d)
        return out

    def snapshot(self, namespace: str | None = None) -> Snapshot:
        cached = self._cache.get(namespace)
        if cached and time.monotonic() - cached[0] < self._cache_ttl:
            return cached[1]
        warnings: list[str] = list(self.privilege_warnings())
        raw = self._fetch_raw(namespace, warnings)
        raw.config_maps = self._platform_config_maps(raw, warnings)
        now = datetime.now(UTC)
        falco = []
        if self._alerts:
            falco = self._alerts.since(now - self._falco_window, namespace=namespace)
        else:
            warnings.append("No Falco alert store configured; runtime signals skipped")
        snap = Snapshot.build(raw, now=now, falco=falco, warnings=warnings)
        self._cache[namespace] = (time.monotonic(), snap)
        return snap

    def logs(self, namespace: str, pod: str, container: str, previous: bool) -> str | None:
        """Last lines of a container log. Needs the optional ``pods/log`` permission (deploy/rbac.yaml)."""
        from kubernetes.client.exceptions import ApiException

        try:
            text = self._core.read_namespaced_pod_log(
                pod,
                namespace,
                container=container,
                previous=previous,
                tail_lines=LOG_TAIL_LINES,
                limit_bytes=LOG_LIMIT_BYTES,
                _request_timeout=10,
            )
        except ApiException as e:
            if e.status in (400, 403, 404):  # no previous instance / not allowed / gone
                return None
            raise
        return str(text) if text is not None else None

    def raw_dump(self, namespace: str | None = None) -> RawCluster:
        """Used by ``kubepilot capture`` to write a fixture directory from a live cluster."""
        warnings: list[str] = []
        raw = self._fetch_raw(namespace, warnings)
        raw.config_maps = self._platform_config_maps(raw, warnings)
        for w in warnings:
            log.warning(w)
        return raw
