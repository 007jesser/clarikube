"""Diagnosis, RBAC and security-triage engines against the demo cluster."""

from __future__ import annotations

from datetime import timedelta

from kubepilot.engine import diagnose, rbac, security
from kubepilot.engine.allowlist import Allowlist
from kubepilot.models import BindingInfo, PolicyRule, RoleInfo, Severity, Subject, WorkloadRef
from tests.conftest import ALLOWLIST


def wl(name: str, ns: str = "shop", kind: str = "Deployment") -> WorkloadRef:
    return WorkloadRef(kind=kind, namespace=ns, name=name)


def titles(findings) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.title for f in findings]


# ---------------------------------------------------------------- diagnosis


def test_oom_correlated_with_rollout(snap) -> None:  # type: ignore[no-untyped-def]
    f = diagnose.diagnose_workload(snap, wl("checkout"))[0]
    assert f.title.startswith("OOMKilled")
    assert f.severity == Severity.HIGH
    assert "lowered the memory limit from 512Mi to 256Mi" in f.explanation
    hint = next(h for h in f.remediations if h.kind == "set-memory-limit")
    assert hint.params == {"container": "checkout", "current": "256Mi", "proposed": "512Mi"}
    assert any(h.kind == "rollback-template" for h in f.remediations)
    assert any(e.source == "rollout" for e in f.evidence)


def test_oom_without_rollout_doubles_limit(snap) -> None:  # type: ignore[no-untyped-def]
    # Pretend the rollout happened long ago: correlation window no longer applies.
    snap.now = snap.now + timedelta(days=2)
    f = diagnose.diagnose_workload(snap, wl("checkout"))[0]
    hint = next(h for h in f.remediations if h.kind == "set-memory-limit")
    assert hint.params["proposed"] == "512Mi"  # 2 x 256Mi
    assert "lowered" not in f.explanation


def test_image_pull_suggests_previous_image(snap) -> None:  # type: ignore[no-untyped-def]
    f = diagnose.diagnose_workload(snap, wl("frontend"))[0]
    assert "does not exist in the registry" in f.explanation
    hint = f.remediations[0]
    assert hint.kind == "set-image" and hint.params["proposed"].endswith("frontend:1.8.2")


def test_unschedulable_request_larger_than_any_node(snap) -> None:  # type: ignore[no-untyped-def]
    f = diagnose.diagnose_workload(snap, wl("worker"))[0]
    assert "can never fit" in f.explanation
    assert f.remediations[0].kind == "set-memory-request"


def test_missing_secret(snap) -> None:  # type: ignore[no-untyped-def]
    f = diagnose.diagnose_workload(snap, wl("api"))[0]
    assert f.category == "config"
    assert f.remediations[0].params == {"kind": "secret", "name": "api-db-credentials", "namespace": "shop"}


def test_healthy_workloads_have_no_issues(snap) -> None:  # type: ignore[no-untyped-def]
    assert diagnose.diagnose_workload(snap, wl("payment-api")) == []
    assert diagnose.diagnose_workload(snap, wl("backup", "batch", "CronJob")) == []


def test_diagnose_all_ranked_and_filtered(snap) -> None:  # type: ignore[no-untyped-def]
    findings = diagnose.diagnose_all(snap)
    assert {f.workload.name for f in findings} == {
        "checkout",
        "frontend",
        "worker",
        "api",
        "orders",  # shop apps
        "search",
        "events-broker",  # data tier pods (OOMKilled OpenSearch, Kafka broker without a volume)
        "cilium",  # CNI agent crash-looping on one node
    }
    assert all(f.severity >= Severity.MEDIUM for f in findings)
    hygiene = diagnose.diagnose_all(snap, include_hygiene=True, min_severity=Severity.LOW)
    assert len(hygiene) >= len(findings)


def test_template_diff(snap) -> None:  # type: ignore[no-untyped-def]
    cur, prev = diagnose.latest_rollout(snap, wl("checkout"))  # type: ignore[misc]
    changes = diagnose.template_diff(prev, cur)
    assert "checkout: memory limit 512Mi → 256Mi" in changes
    assert any("image" in c and "2.8.0" in c for c in changes)


# ---------------------------------------------------------------- rbac


def _sa_binding(kind: str, role_kind: str, role: str, ns: str | None) -> BindingInfo:
    return BindingInfo(
        kind=kind,  # type: ignore[arg-type]
        namespace=ns,
        name="b",
        role_kind=role_kind,  # type: ignore[arg-type]
        role_name=role,
        subjects=[Subject(kind="ServiceAccount", name="sa", namespace="app")],
    )


def test_rolebinding_to_clusterrole_is_namespace_scoped() -> None:
    roles = [
        RoleInfo(
            kind="ClusterRole",
            namespace=None,
            name="reader",
            rules=[PolicyRule(api_groups=[""], resources=["secrets"], verbs=["list"])],
        )
    ]
    grants = rbac.grants_for("app", "sa", roles, [_sa_binding("RoleBinding", "ClusterRole", "reader", "app")])
    risky = rbac.risky_permissions(grants)
    assert risky[0].code == "secrets-read" and risky[0].scope == "app" and risky[0].points == 15


def test_cluster_admin_via_group() -> None:
    roles = [
        RoleInfo(
            kind="ClusterRole",
            namespace=None,
            name="cluster-admin",
            rules=[PolicyRule(api_groups=["*"], resources=["*"], verbs=["*"])],
        )
    ]
    b = BindingInfo(
        kind="ClusterRoleBinding",
        namespace=None,
        name="oops",
        role_kind="ClusterRole",
        role_name="cluster-admin",
        subjects=[Subject(kind="Group", name="system:serviceaccounts")],
    )
    risky = rbac.risky_permissions(rbac.grants_for("app", "sa", roles, [b]))
    assert risky[0].code == "cluster-admin" and risky[0].scope == "cluster" and risky[0].points == 30


def test_resource_names_restrict_secret_read() -> None:
    roles = [
        RoleInfo(
            kind="Role",
            namespace="app",
            name="r",
            rules=[PolicyRule(api_groups=[""], resources=["secrets"], verbs=["get"], resource_names=["one"])],
        )
    ]
    grants = rbac.grants_for("app", "sa", roles, [_sa_binding("RoleBinding", "Role", "r", "app")])
    assert rbac.risky_permissions(grants) == []


def test_other_sa_not_matched(snap) -> None:  # type: ignore[no-untyped-def]
    assert rbac.grants_for("shop", "checkout", snap.roles, snap.bindings) == []


# ---------------------------------------------------------------- security triage


def test_payment_api_is_top_critical_incident(snap) -> None:  # type: ignore[no-untyped-def]
    incidents = security.triage(snap, Allowlist.load(ALLOWLIST))
    top = incidents[0]
    assert top.workload == wl("payment-api")
    assert top.severity == Severity.CRITICAL and top.score == 100
    assert "LIKELY COMPROMISE" in top.summary
    kinds = {h.kind for h in top.remediations}
    assert {
        "isolate-workload",
        "harden-security-context",
        "restrict-ingress",
        "reduce-rbac",
        "rebuild-image",
        "rotate-credentials",
    } <= kinds
    assert any(s.startswith("correlated") for s in top.signals)


def test_allowlist_suppresses_backup_noise(snap) -> None:  # type: ignore[no-untyped-def]
    inc = next(i for i in security.triage(snap, Allowlist.load(ALLOWLIST)) if i.workload.name == "backup")
    assert inc.suppressed_alerts == 3
    assert inc.severity <= Severity.LOW
    assert not any("Falco" in s for s in inc.signals)


def test_without_allowlist_backup_alerts_count(snap) -> None:  # type: ignore[no-untyped-def]
    inc = next(i for i in security.triage(snap) if i.workload.name == "backup")
    assert inc.suppressed_alerts == 0
    assert any("Falco" in s for s in inc.signals)


def test_since_window_excludes_old_alerts(snap) -> None:  # type: ignore[no-untyped-def]
    incidents = security.triage(snap, since=timedelta(minutes=10))  # all alerts are ~47+ minutes old
    top = next(i for i in incidents if i.workload.name == "payment-api")
    assert not any("Falco" in s for s in top.signals)
    assert not any(s.startswith("correlated") for s in top.signals)  # no runtime => no multiplier


def test_min_score_filter(snap) -> None:  # type: ignore[no-untyped-def]
    assert all(i.score >= 45 for i in security.triage(snap, min_score=45))


def test_severity_bands() -> None:
    assert security.severity_for(70) == Severity.CRITICAL
    assert security.severity_for(45) == Severity.HIGH
    assert security.severity_for(25) == Severity.MEDIUM
    assert security.severity_for(10) == Severity.LOW
    assert security.severity_for(9) == Severity.INFO


def test_injection_in_alert_is_flagged_in_evidence(snap) -> None:  # type: ignore[no-untyped-def]
    top = security.triage(snap, Allowlist.load(ALLOWLIST))[0]
    falco_ev = [e.detail for e in top.evidence if e.source == "falco"]
    assert any("possible prompt-injection" in d for d in falco_ev)
