"""`clarikube ask` agent loop against a scripted OpenAI-compatible endpoint."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clarikube import agent
from clarikube.changes import PlanStore
from clarikube.service import Clarikube


class Scripted:
    """Fake chat endpoint: returns the queued messages in order and records requests."""

    def __init__(self, *messages: dict[str, Any]) -> None:
        self.queue = list(messages)
        self.requests: list[dict[str, Any]] = []

    def __call__(self, url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        self.requests.append({"url": url, "payload": json.loads(json.dumps(payload)), "headers": headers})
        msg = self.queue.pop(0)
        return {"choices": [{"message": msg}], "usage": {"prompt_tokens": 100, "completion_tokens": 10}}


def call(tool: str, **args: Any) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {"id": f"c-{tool}", "type": "function", "function": {"name": tool, "arguments": json.dumps(args)}}
        ],
    }


def test_tool_loop_and_answer(kp: Clarikube) -> None:
    fake = Scripted(
        call("diagnose_workload", namespace="shop", name="orders"),
        {"role": "assistant", "content": "Kafka data/events is the root cause."},
    )
    tr = agent.ask(kp, "why is orders crashing?", model="m", base_url="http://llm/v1", api_key="k", post=fake)
    assert tr.answer == "Kafka data/events is the root cause."
    assert [s.tool for s in tr.steps] == ["diagnose_workload"] and tr.steps[0].ok
    assert (tr.prompt_tokens, tr.completion_tokens) == (200, 20)
    first = fake.requests[0]
    assert first["url"] == "http://llm/v1/chat/completions"
    assert first["headers"] == {"Authorization": "Bearer k"}
    offered = {t["function"]["name"] for t in first["payload"]["tools"]}
    assert "commit_plan" not in offered and {"diagnose_workload", "diagnose_component"} <= offered
    tool_msg = fake.requests[1]["payload"]["messages"][-1]
    assert tool_msg["role"] == "tool" and "Likely root cause" in tool_msg["content"]
    assert "sk_live" not in tool_msg["content"]


def test_commit_is_not_available_to_the_model(kp: Clarikube) -> None:
    fake = Scripted(call("commit_plan", plan_id="x", approval_token="y"), {"role": "assistant", "content": "ok"})
    tr = agent.ask(kp, "commit it", model="m", base_url="http://llm/v1", post=fake)
    assert tr.steps[0].ok is False
    assert "unavailable tool" in fake.requests[1]["payload"]["messages"][-1]["content"]


def test_inline_json_tool_call_from_small_models(kp: Clarikube) -> None:
    fake = Scripted(
        {
            "role": "assistant",
            "content": 'I will check. {"name": "list_components", "arguments": {"namespace": "data"}}',
        },
        {"role": "assistant", "content": "5 components."},
    )
    tr = agent.ask(kp, "what runs in data?", model="m", base_url="http://llm/v1", post=fake)
    assert [s.tool for s in tr.steps] == ["list_components"] and tr.answer == "5 components."


def test_truncation_and_max_steps(kp: Clarikube) -> None:
    fake = Scripted(*[call("cluster_health")] * 3)
    tr = agent.ask(kp, "loop", model="m", base_url="http://llm/v1", post=fake, max_steps=3, max_tool_chars=200)
    assert tr.stopped == "max_steps" and len(tr.steps) == 3
    assert "[truncated" in fake.requests[1]["payload"]["messages"][-1]["content"]
    assert json.loads(json.dumps(tr.to_json()))["stopped"] == "max_steps"


def test_human_commit_path(kp: Clarikube, gitops_repo: Path) -> None:
    p = kp.plan_remediation("data", "events")
    store: PlanStore = kp._require_plans()
    with pytest.raises(PermissionError, match="token required"):
        store.commit(p["id"], None)
    done = store.commit(p["id"], None, human=True)
    assert done.status == "committed" and done.branch
    assert any(e["event"] == "plan_approved_terminal" for e in store.history(50))


def test_cli_commit_refuses_without_tty(kp: Clarikube, monkeypatch: pytest.MonkeyPatch) -> None:
    from clarikube import cli

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli._confirm_on_tty("? ") is False
