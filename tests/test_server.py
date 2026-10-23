"""End-to-end through the MCP protocol (in-memory transport) and the Falco ingest endpoint."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from mcp.client.client import Client
from starlette.testclient import TestClient

from kubepilot.server import create_server
from kubepilot.service import KubePilot
from kubepilot.source.alerts import AlertStore, make_ingest_app

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def payload(result: Any) -> dict[str, Any]:
    if getattr(result, "structured_content", None):
        sc = result.structured_content
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    text = "".join(getattr(c, "text", "") for c in result.content)
    return json.loads(text)


async def test_tools_listed_with_annotations(kp: KubePilot) -> None:
    async with Client(create_server(kp)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert {
            "cluster_health",
            "diagnose_workload",
            "security_triage",
            "investigate_security",
            "plan_remediation",
            "commit_plan",
            "list_plans",
            "change_history",
            "find_problems",
            "recent_events",
        } <= set(tools)
        assert tools["cluster_health"].annotations.read_only_hint is True
        assert tools["commit_plan"].annotations.read_only_hint is False
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        assert {"triage_cluster", "fix_workload", "incident_response"} <= prompts


async def test_cluster_health_via_mcp(kp: KubePilot) -> None:
    async with Client(create_server(kp)) as client:
        data = payload(await client.call_tool("cluster_health", {}))
        assert data["source"] == "fixture"
        assert {i["workload"] for i in data["reliability_issues"]} >= {"Deployment/shop/checkout"}
        assert data["security_incidents"][0]["workload"] == "Deployment/shop/payment-api"


async def test_injection_flagged_through_mcp(kp: KubePilot) -> None:
    async with Client(create_server(kp)) as client:
        data = payload(await client.call_tool("investigate_security", {"namespace": "shop", "name": "payment-api"}))
        details = [e["detail"] for e in data["incident"]["evidence"]]
        flagged = [d for d in details if "kubectl delete" in d]
        assert flagged and all(d.startswith("[kubepilot: possible prompt-injection") for d in flagged)


async def test_plan_and_commit_via_mcp(kp: KubePilot) -> None:
    async with Client(create_server(kp)) as client:
        plan = payload(await client.call_tool("plan_remediation", {"namespace": "shop", "name": "frontend"}))
        assert "frontend:1.8.2" in plan["files"][0]["diff"]
        res = payload(
            await client.call_tool("commit_plan", {"plan_id": plan["id"], "approval_token": plan["approval_token"]})
        )
        assert res["status"] == "committed"


async def test_errors_are_clean_tool_errors(kp: KubePilot) -> None:
    async with Client(create_server(kp)) as client:
        r = await client.call_tool("diagnose_workload", {"namespace": "shop", "name": "ghost"})
        assert r.is_error
        text = "".join(getattr(c, "text", "") for c in r.content)
        assert "NotFound" in text and "Traceback" not in text
        r = await client.call_tool("diagnose_workload", {"namespace": "../etc", "name": "x"})
        assert r.is_error and "invalid Kubernetes name" in "".join(getattr(c, "text", "") for c in r.content)
        r = await client.call_tool("commit_plan", {"plan_id": "deadbeef0000", "approval_token": "x"})
        assert r.is_error


# ---------------------------------------------------------------- ingest


def _falco(rule: str = "Terminal shell in container") -> dict[str, Any]:
    return {
        "time": datetime.now(UTC).isoformat(),
        "rule": rule,
        "priority": "Notice",
        "output": "shell",
        "output_fields": {"k8s.ns.name": "shop", "k8s.pod.name": "p"},
    }


def test_ingest_stores_and_authenticates() -> None:
    store = AlertStore(":memory:")
    client = TestClient(make_ingest_app(store, token="s3cret"))
    assert client.post("/falco", json=_falco()).status_code == 401
    r = client.post("/falco", json=_falco(), headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.json() == {"stored": 1}
    assert client.post("/falco", content=b"{not json", headers={"Authorization": "Bearer s3cret"}).status_code == 400
    assert client.post("/falco", content=b"x" * 300_000, headers={"Authorization": "Bearer s3cret"}).status_code == 413
    alerts = store.since(datetime.now(UTC) - timedelta(minutes=1))
    assert len(alerts) == 1 and alerts[0].pod == "p"
    assert store.since(datetime.now(UTC) - timedelta(minutes=1), namespace="other") == []


def test_alert_retention() -> None:
    store = AlertStore(":memory:", retention=timedelta(days=1))
    old = _falco()
    old["time"] = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    store.add_raw(old)
    store.add_raw(_falco())
    assert store.prune(datetime.now(UTC)) == 1
