"""Policy guard, remediation edits and the plan → approve → commit pipeline."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from clarikube import policy, remediation
from clarikube.changes import PlanStore
from clarikube.models import RemediationHint, WorkloadRef
from clarikube.remediation import FileChange, RemediationError, RemediationResult
from clarikube.service import Clarikube
from tests.conftest import git, make_settings

# ---------------------------------------------------------------- policy guard


def _deploy(container: dict[str, object], pod: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "kind": "Deployment",
        "spec": {"template": {"spec": {**(pod or {}), "containers": [{"name": "c", **container}]}}},
    }


def test_policy_introduced_vs_preexisting() -> None:
    before = _deploy({"image": "x:latest"})
    after = _deploy({"image": "x:latest", "securityContext": {"privileged": True}})
    res = policy.compare(before, after)
    statuses = {(r.rule, r.status) for r in res}
    assert ("no-privileged", "introduced") in statuses
    assert ("pinned-image", "pre-existing") in statuses
    assert [r.rule for r in policy.blocking(res)] == ["no-privileged"]


def test_policy_resolved() -> None:
    before = _deploy({"image": "x:1", "securityContext": {"privileged": True}})
    after = _deploy({"image": "x:1"})
    assert ("no-privileged", "resolved") in {(r.rule, r.status) for r in policy.compare(before, after)}


@pytest.mark.parametrize(
    ("obj", "rule"),
    [
        (_deploy({"image": "x:1"}, {"hostNetwork": True}), "host-namespaces"),
        (_deploy({"image": "x:1"}, {"volumes": [{"name": "h", "hostPath": {"path": "/"}}]}), "no-hostpath"),
        (
            _deploy({"image": "x:1", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}),
            "no-dangerous-caps",
        ),
        (_deploy({"image": "x"}), "pinned-image"),
        (_deploy({"image": "x:1", "securityContext": {"runAsUser": 0}}), "non-root"),
    ],
)
def test_policy_deny_rules(obj: dict[str, object], rule: str) -> None:
    assert rule in {v.rule for v in policy.check(obj) if v.level == "deny"}


def test_policy_digest_is_pinned() -> None:
    assert "pinned-image" not in {v.rule for v in policy.check(_deploy({"image": "x@sha256:" + "a" * 64}))}


def test_policy_ignores_other_kinds() -> None:
    assert policy.check({"kind": "ConfigMap"}) == set()


# ---------------------------------------------------------------- remediation edits


def test_edit_preserves_comments_and_style(gitops_repo: Path, snap) -> None:  # type: ignore[no-untyped-def]
    hint = RemediationHint(
        kind="set-memory-limit",
        summary="",
        params={"container": "checkout", "current": "256Mi", "proposed": "512Mi"},
    )
    res = remediation.build(
        gitops_repo, snap, WorkloadRef(kind="Deployment", namespace="shop", name="checkout"), [hint]
    )
    (change,) = res.changes
    assert "# Checkout service — owned by team-payments" in change.after
    assert "memory: 128Mi   # lowered in 2.8.0 to save costs" in change.after
    diff_lines = [
        ln for ln in change.diff().splitlines() if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))
    ]
    assert diff_lines == ["-              memory: 256Mi", "+              memory: 512Mi"]


def test_netpol_added_and_registered_in_kustomization(gitops_repo: Path, snap) -> None:  # type: ignore[no-untyped-def]
    hint = RemediationHint(kind="isolate-workload", summary="", params={})
    res = remediation.build(
        gitops_repo, snap, WorkloadRef(kind="Deployment", namespace="shop", name="payment-api"), [hint]
    )
    paths = {c.path for c in res.changes}
    assert paths == {"apps/shop/clarikube-payment-api-isolate.yaml", "apps/shop/kustomization.yaml"}
    np = next(c for c in res.changes if c.path.endswith("isolate.yaml"))
    assert np.before is None and "policyTypes:\n    - Ingress\n    - Egress" in np.after
    assert "app: payment-api" in np.after


def test_manual_hints_are_not_automated(gitops_repo: Path, snap) -> None:  # type: ignore[no-untyped-def]
    hint = RemediationHint(kind="rotate-credentials", summary="rotate it", params={})
    res = remediation.build(
        gitops_repo, snap, WorkloadRef(kind="Deployment", namespace="shop", name="payment-api"), [hint]
    )
    assert res.changes == [] and res.manual == ["rotate it"]


def test_missing_manifest(gitops_repo: Path, snap) -> None:  # type: ignore[no-untyped-def]
    hint = RemediationHint(kind="set-image", summary="", params={"container": "x", "proposed": "y:1"})
    with pytest.raises(RemediationError, match="no manifest"):
        remediation.build(gitops_repo, snap, WorkloadRef(kind="Deployment", namespace="shop", name="nope"), [hint])


def test_ambiguous_manifest(gitops_repo: Path, snap) -> None:  # type: ignore[no-untyped-def]
    (gitops_repo / "apps" / "shop" / "dup.yaml").write_text(
        (gitops_repo / "apps" / "shop" / "frontend.yaml").read_text()
    )
    hint = RemediationHint(kind="set-image", summary="", params={"container": "frontend", "proposed": "y:1"})
    with pytest.raises(RemediationError, match="ambiguous"):
        remediation.build(gitops_repo, snap, WorkloadRef(kind="Deployment", namespace="shop", name="frontend"), [hint])


def test_helm_templates_are_skipped(gitops_repo: Path) -> None:
    from clarikube.gitops import manifests

    (gitops_repo / "tpl.yaml").write_text("kind: Deployment\nmetadata:\n  name: {{ .Values.name }}\n")
    assert all(d.path.name != "tpl.yaml" for d in manifests.scan(gitops_repo))


# ---------------------------------------------------------------- plan pipeline


def test_full_flow_commits_on_branch_without_touching_checkout(kp: Clarikube, gitops_repo: Path) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    assert not plan["blocked"]
    assert plan["applied"] == ["checkout: limits.memory 256Mi → 512Mi"]
    assert "approval_token" in plan and "token_sha" not in plan
    res = kp.commit_plan(plan["id"], plan["approval_token"])
    assert res["status"] == "committed" and res["branch"].startswith("clarikube/checkout-")
    # user's checkout untouched
    assert git(gitops_repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(gitops_repo, "status", "--porcelain") == ""
    assert "memory: 256Mi" in (gitops_repo / "apps/shop/checkout.yaml").read_text()
    # branch has the change and a descriptive message
    content = git(gitops_repo, "show", f"{res['branch']}:apps/shop/checkout.yaml")
    assert "memory: 512Mi" in content
    msg = git(gitops_repo, "log", "-1", "--format=%B", res["branch"])
    assert "lowered the memory limit" in msg and f"Plan-Id: {plan['id']}" in msg
    assert git(gitops_repo, "worktree", "list").count("\n") == 0  # temp worktree cleaned up
    # cannot commit twice
    with pytest.raises(PermissionError, match="committed"):
        kp.commit_plan(plan["id"], plan["approval_token"])


def test_dry_run_writes_nothing(tmp_path: Path, gitops_repo: Path, demo_source) -> None:  # type: ignore[no-untyped-def]
    kp = Clarikube(demo_source, make_settings(tmp_path, gitops_repo, dry_run=True))
    plan = kp.plan_remediation("shop", "checkout")
    res = kp.commit_plan(plan["id"], plan["approval_token"])
    assert res["status"].startswith("dry-run")
    assert git(gitops_repo, "branch", "--list", "clarikube/*") == ""


def test_bad_token_rejected(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    with pytest.raises(PermissionError, match="invalid approval token"):
        kp.commit_plan(plan["id"], "guess")


def test_expired_plan(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    store = kp.plans
    assert store is not None
    from datetime import UTC, datetime

    with pytest.raises(PermissionError, match="expired"):
        store.commit(plan["id"], plan["approval_token"], now=datetime.now(UTC) + timedelta(hours=2))


def test_stale_head(kp: Clarikube, gitops_repo: Path) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    (gitops_repo / "x.txt").write_text("x")
    git(gitops_repo, "add", "x.txt")
    git(gitops_repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "other")
    with pytest.raises(PermissionError, match="HEAD moved"):
        kp.commit_plan(plan["id"], plan["approval_token"])


def test_stale_file(kp: Clarikube, gitops_repo: Path) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    f = gitops_repo / "apps/shop/checkout.yaml"
    f.write_text(f.read_text() + "\n# edited\n")
    with pytest.raises(PermissionError, match="changed since planning"):
        kp.commit_plan(plan["id"], plan["approval_token"])


def test_cli_approval_mode(tmp_path: Path, gitops_repo: Path, demo_source) -> None:  # type: ignore[no-untyped-def]
    kp = Clarikube(demo_source, make_settings(tmp_path, gitops_repo, approval_mode="cli"))
    plan = kp.plan_remediation("shop", "frontend")
    with pytest.raises(PermissionError, match="clarikube approve"):
        kp.commit_plan(plan["id"], plan["approval_token"])
    assert kp.plans is not None
    kp.plans.approve_cli(plan["id"])
    assert kp.commit_plan(plan["id"], plan["approval_token"])["status"] == "committed"


def test_blocked_plan_cannot_commit(tmp_path: Path, gitops_repo: Path) -> None:
    store = PlanStore(gitops_repo, tmp_path / "s", dry_run=False)
    before = (gitops_repo / "apps/shop/frontend.yaml").read_text()
    after = before.replace("containers:", "hostNetwork: true\n      containers:")
    pol = policy.compare(_deploy({"image": "x:1"}), _deploy({"image": "x:1"}, {"hostNetwork": True}))
    result = RemediationResult(
        changes=[FileChange(path="apps/shop/frontend.yaml", before=before, after=after, policy=pol)],
        applied=["x"],
        manual=[],
        notes=[],
    )
    plan, token = store.create(WorkloadRef(kind="Deployment", namespace="shop", name="frontend"), result, "test")
    assert plan.blocked and "host-namespaces" in plan.blocking_reasons[0]
    with pytest.raises(PermissionError, match="blocked"):
        store.commit(plan.id, token)


def test_path_traversal_refused(tmp_path: Path, gitops_repo: Path) -> None:
    store = PlanStore(gitops_repo, tmp_path / "s", dry_run=False)
    result = RemediationResult(
        changes=[FileChange(path="../../escape.yaml", before=None, after="x: 1\n")],
        applied=["x"],
        manual=[],
        notes=[],
    )
    plan, token = store.create(WorkloadRef(kind="Deployment", namespace="shop", name="frontend"), result, "test")
    with pytest.raises(PermissionError, match="outside the repo"):
        store.commit(plan.id, token)
    assert not (tmp_path / "escape.yaml").exists()


def test_invalid_plan_id(tmp_path: Path, gitops_repo: Path) -> None:
    store = PlanStore(gitops_repo, tmp_path / "s")
    with pytest.raises(ValueError):
        store.get("../../etc/passwd")


def test_missing_secret_plan_is_manual_only(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "api")
    assert plan["blocked"] and plan["files"] == []
    assert any("api-db-credentials" in m for m in plan["manual"])


def test_explicit_kinds_and_unknown_kind(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "checkout", ["rollback-template"])
    assert any("image" in a for a in plan["applied"])
    with pytest.raises(ValueError, match="not applicable"):
        kp.plan_remediation("shop", "checkout", ["isolate-workload"])


def test_security_plan_for_compromised_workload(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "payment-api")
    paths = {f["path"] for f in plan["files"]}
    assert "apps/shop/payment-api.yaml" in paths
    assert "apps/shop/clarikube-payment-api-ingress.yaml" in paths
    assert any("Rebuild the image" in m for m in plan["manual"])
    assert not plan["blocked"]


def test_audit_log(kp: Clarikube) -> None:
    plan = kp.plan_remediation("shop", "checkout")
    kp.commit_plan(plan["id"], plan["approval_token"])
    events = [e["event"] for e in kp.change_history()["events"]]
    assert events[-2:] == ["plan_created", "plan_committed"]
