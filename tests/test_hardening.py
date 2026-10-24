"""Pre-release hardening: capture redaction, ingest limits/auth, git hooks never executed."""

from __future__ import annotations

from pathlib import Path

import pytest
from starlette.testclient import TestClient

from kubepilot import cli
from kubepilot.redact import REDACTED, redact_objects
from kubepilot.source.alerts import MAX_BODY_BYTES, AlertStore, make_ingest_app
from tests.conftest import git, make_settings

# ---------------------------------------------------------------- capture redaction


def test_redaction_removes_secrets_from_pod_specs() -> None:
    pod = {
        "kind": "Pod",
        "metadata": {
            "name": "p",
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": '{"env":[{"name":"DB_PASS","value":"hunter2"}]}',
                "vault.example.com/token": "s.abc",
                "team": "payments",
            },
            "managedFields": [{"manager": "kubectl"}],
        },
        "spec": {
            "containers": [
                {
                    "name": "c",
                    "image": "app:1",
                    "env": [
                        {"name": "DB_PASS", "value": "hunter2"},
                        {"name": "FROM_SECRET", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
                    ],
                    "args": ["--port=8080", "--password=hunter2"],
                }
            ]
        },
    }
    (out,) = redact_objects([pod])
    text = str(out)
    assert "hunter2" not in text and "s.abc" not in text
    assert "managedFields" not in out["metadata"]
    assert "kubectl.kubernetes.io/last-applied-configuration" not in out["metadata"]["annotations"]
    assert out["metadata"]["annotations"]["team"] == "payments"
    c = out["spec"]["containers"][0]
    assert c["env"][0] == {"name": "DB_PASS", "value": REDACTED}
    assert c["env"][1]["valueFrom"]["secretKeyRef"]["name"] == "s"  # references are fine, they hold no value
    assert c["args"] == ["--port=8080", REDACTED]
    assert c["image"] == "app:1"


# ---------------------------------------------------------------- ingest


def test_ingest_rejects_oversize_declared_length() -> None:
    client = TestClient(make_ingest_app(AlertStore(":memory:"), token="t"))
    r = client.post(
        "/falco",
        content=b"{}",
        headers={"Authorization": "Bearer t", "Content-Length": str(MAX_BODY_BYTES + 1)},
    )
    assert r.status_code == 413


def test_ingest_rejects_oversize_streamed_body() -> None:
    client = TestClient(make_ingest_app(AlertStore(":memory:"), token="t"))

    def gen():  # type: ignore[no-untyped-def]
        for _ in range(40):
            yield b"x" * 10_000  # 400 KB, chunked: no Content-Length

    r = client.post("/falco", content=gen(), headers={"Authorization": "Bearer t"})
    assert r.status_code == 413


def test_ingest_cli_refuses_without_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("KUBEPILOT_INGEST_TOKEN", raising=False)
    monkeypatch.delenv("KUBEPILOT_INGEST_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.setenv("KUBEPILOT_STATE_DIR", str(tmp_path))
    assert cli.main(["ingest"]) == 2


# ---------------------------------------------------------------- git hooks


def test_repo_hooks_are_never_executed(tmp_path: Path, gitops_repo: Path, demo_source) -> None:  # type: ignore[no-untyped-def]
    from kubepilot.service import KubePilot

    marker = tmp_path / "hook-ran"
    hooks = gitops_repo / ".git" / "hooks"
    for name in ("post-checkout", "pre-commit", "commit-msg", "post-commit"):
        h = hooks / name
        h.write_text(f"#!/bin/sh\necho {name} >> {marker}\n")
        h.chmod(0o755)
    kp = KubePilot(demo_source, make_settings(tmp_path, gitops_repo))
    plan = kp.plan_remediation("shop", "checkout")
    res = kp.commit_plan(plan["id"], plan["approval_token"])
    assert res["status"] == "committed"
    assert not marker.exists(), marker.read_text() if marker.exists() else ""
    assert git(gitops_repo, "branch", "--list", "kubepilot/*")


# ---------------------------------------------------------------- packaged demo (PyPI users have no repo)


def test_demo_data_ships_inside_the_package() -> None:
    from kubepilot import demo

    assert (demo.CLUSTER / "meta.yaml").is_file()
    assert (demo.GITOPS_REPO / "apps" / "shop" / "checkout.yaml").is_file()
    assert demo.ALLOWLIST.is_file()


def test_demo_command_runs(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "checkout" in out and "payment-api" in out


def test_demo_setup_creates_repo_and_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["demo", "--setup", str(tmp_path / "d")]) == 0
    assert git(tmp_path / "d" / "repo", "log", "--oneline")
    out = capsys.readouterr().out
    assert "claude mcp add --scope user kubepilot-demo" in out
    assert "uv --directory" in out  # source checkout -> runnable before the PyPI release
    assert cli.main(["demo", "--setup", str(tmp_path / "d")]) == 2  # refuses to overwrite


# ---------------------------------------------------------------- platform noise (found on the real k3s lab)


def test_platform_namespaces_hidden_from_security_views(tmp_path: Path, gitops_repo: Path, demo_source) -> None:  # type: ignore[no-untyped-def]
    from kubepilot.service import KubePilot

    s = make_settings(tmp_path, gitops_repo, system_namespaces=frozenset({"batch"}))
    kp = KubePilot(demo_source, s)
    tri = kp.security_triage()
    assert all("/batch/" not in i["workload"] for i in tri["incidents"])
    assert tri["platform_incidents_hidden"] == 1
    assert any("/batch/" in i["workload"] for i in kp.security_triage(include_system=True)["incidents"])
    assert any("/batch/" in i["workload"] for i in kp.security_triage(namespace="batch")["incidents"])
    assert kp.cluster_health()["platform_incidents_hidden"] == 0  # backup scores < 45 anyway


def test_system_namespaces_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from kubepilot.config import Settings

    monkeypatch.setenv("KUBEPILOT_SYSTEM_NAMESPACES", "a, b ,")
    assert Settings.from_env().system_namespaces == frozenset({"a", "b"})
    monkeypatch.delenv("KUBEPILOT_SYSTEM_NAMESPACES")
    assert "falco" in Settings.from_env().system_namespaces


def test_capture_keeps_bare_addresses_but_redacts_everything_else() -> None:
    from kubepilot.redact import REDACTED, redact_objects

    pod = {
        "spec": {
            "containers": [
                {
                    "env": [
                        {"name": "SEARCH_URL", "value": "http://search.data:9200"},
                        {"name": "KAFKA", "value": "events-kafka-bootstrap.data.svc:9092"},
                        {"name": "DB_URL", "value": "postgres://app:s3cret@pg-rw.data:5432/app"},
                        {"name": "API_TOKEN", "value": "redis.data:6379"},
                        {"name": "MODE", "value": "fast and loud"},
                        {"name": "Q", "value": "http://x.data:80/?key=abc"},
                        {"name": "APP_X", "value": "Tr0ub4dor"},
                    ]
                }
            ]
        }
    }
    env = redact_objects([pod])[0]["spec"]["containers"][0]["env"]
    vals = {e["name"]: e["value"] for e in env}
    assert vals["SEARCH_URL"] == "http://search.data:9200"
    assert vals["KAFKA"] == "events-kafka-bootstrap.data.svc:9092"
    assert vals["DB_URL"] == REDACTED and vals["API_TOKEN"] == REDACTED
    assert vals["MODE"] == REDACTED and vals["Q"] == REDACTED
    assert vals["APP_X"] == REDACTED  # a single word may be a password
