"""Effective RBAC permissions of a ServiceAccount and detection of risky grants."""

from __future__ import annotations

from dataclasses import dataclass

from kubemedic.models import BindingInfo, PolicyRule, RoleInfo, Subject


@dataclass(frozen=True)
class Grant:
    rule: PolicyRule
    scope: str  # "cluster" or the namespace
    via: str  # e.g. "RoleBinding shop/payment-api -> Role payment-api"


@dataclass(frozen=True)
class RiskyPermission:
    code: str  # cluster-admin | secrets-read | pod-exec | workload-create | rbac-escalation | node-proxy
    description: str
    scope: str
    via: str
    points: int


def _subject_matches(s: Subject, sa_ns: str, sa_name: str) -> bool:
    if s.kind == "ServiceAccount":
        return s.name == sa_name and (s.namespace or "") == sa_ns
    if s.kind == "Group":
        return s.name in ("system:serviceaccounts", f"system:serviceaccounts:{sa_ns}", "system:authenticated")
    if s.kind == "User":
        return s.name == f"system:serviceaccount:{sa_ns}:{sa_name}"
    return False


def grants_for(sa_ns: str, sa_name: str, roles: list[RoleInfo], bindings: list[BindingInfo]) -> list[Grant]:
    index = {(r.kind, r.namespace, r.name): r for r in roles}
    out: list[Grant] = []
    for b in bindings:
        if not any(_subject_matches(s, sa_ns, sa_name) for s in b.subjects):
            continue
        if b.kind == "ClusterRoleBinding":
            role = index.get(("ClusterRole", None, b.role_name))
            scope = "cluster"
        else:
            role = (
                index.get(("ClusterRole", None, b.role_name))
                if b.role_kind == "ClusterRole"
                else index.get(("Role", b.namespace, b.role_name))
            )
            scope = b.namespace or ""
        if role is None:
            continue
        where = f"{b.namespace}/" if b.namespace else ""
        via = f"{b.kind} {where}{b.name} -> {b.role_kind} {b.role_name}"
        out.extend(Grant(rule=r, scope=scope, via=via) for r in role.rules)
    return out


def _has(values: list[str], *wanted: str) -> bool:
    return "*" in values or any(w in values for w in wanted)


_WORKLOAD_RESOURCES = ("pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs")


def risky_permissions(grants: list[Grant]) -> list[RiskyPermission]:
    found: dict[tuple[str, str], RiskyPermission] = {}

    def add(code: str, desc: str, g: Grant, points: int) -> None:
        key = (code, g.scope)
        if key not in found or found[key].points < points:
            found[key] = RiskyPermission(code, desc, g.scope, g.via, points)

    for g in grants:
        r = g.rule
        where = "cluster-wide" if g.scope == "cluster" else f"in namespace {g.scope}"
        if "*" in r.verbs and "*" in r.resources and _has(r.api_groups, "*"):
            add("cluster-admin", f"full admin (*/*/*) {where}", g, 30 if g.scope == "cluster" else 20)
            continue
        core = _has(r.api_groups, "")
        if core and _has(r.resources, "secrets") and _has(r.verbs, "get", "list", "watch") and not r.resource_names:
            add("secrets-read", f"can read all secrets {where}", g, 20 if g.scope == "cluster" else 15)
        if core and _has(r.resources, "pods/exec", "pods/attach") and _has(r.verbs, "create", "get"):
            add("pod-exec", f"can exec into pods {where}", g, 10)
        if _has(r.resources, *_WORKLOAD_RESOURCES) and _has(r.verbs, "create", "update", "patch"):
            add("workload-create", f"can create/modify workloads {where} (privilege escalation path)", g, 10)
        if _has(r.api_groups, "rbac.authorization.k8s.io") and _has(r.verbs, "escalate", "bind", "impersonate"):
            add("rbac-escalation", f"can escalate/bind/impersonate {where}", g, 20)
        if core and _has(r.resources, "nodes/proxy"):
            add("node-proxy", f"can proxy to kubelets {where}", g, 20)
    return sorted(found.values(), key=lambda p: -p.points)
