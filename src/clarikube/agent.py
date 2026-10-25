"""`clarikube ask`: a minimal agent loop for any OpenAI-compatible chat endpoint (Ollama, LM Studio, vLLM,
llama.cpp server, OpenAI, ...). Lets small local models use clarikube without an MCP client.

The model sees exactly the MCP tools (same schemas, same server) minus ``commit_plan``: committing stays a
human action (``clarikube commit <plan-id>`` at a terminal, or an MCP client with approval). Tool results
are truncated for small context windows. A JSON transcript (tool calls, timings, token usage) can be saved
for benchmarking.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp.client.client import Client

from clarikube.server import INSTRUCTIONS, create_server
from clarikube.service import Clarikube

Post = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]

HIDDEN_TOOLS = {"commit_plan"}  # never offered to the model in `ask`
SYSTEM = (
    INSTRUCTIONS
    + """
You are running inside `clarikube ask`. You cannot commit changes: if a fix is appropriate, call
plan_remediation and report the plan id, the diff summary and the notes; the human commits it.
Use tools before answering. Answer concisely: root cause, evidence, recommended fix."""
)


def http_post(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"LLM base URL must be http(s): {url!r}")
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 - scheme checked above
            data: dict[str, Any] = json.loads(resp.read())
            return data
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"LLM endpoint returned {e.code}: {e.read()[:300]!r}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"cannot reach LLM endpoint {url}: {e.reason}") from e


@dataclass
class Step:
    tool: str
    arguments: dict[str, Any]
    ok: bool
    chars: int
    seconds: float


@dataclass
class Transcript:
    question: str
    model: str
    steps: list[Step] = field(default_factory=list)
    answer: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    seconds: float = 0.0
    stopped: str = "answer"  # answer | max_steps | error

    def to_json(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "model": self.model,
            "answer": self.answer,
            "stopped": self.stopped,
            "seconds": round(self.seconds, 2),
            "tokens": {"prompt": self.prompt_tokens, "completion": self.completion_tokens},
            "steps": [s.__dict__ for s in self.steps],
        }


_INLINE_CALL = re.compile(r"\{.*\}", re.S)


def _inline_tool_call(content: str, names: set[str]) -> tuple[str, dict[str, Any]] | None:
    """Some small models print a tool call as JSON text instead of using tool_calls."""
    m = _INLINE_CALL.search(content or "")
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    name = obj.get("name") or obj.get("tool")
    args = obj.get("arguments") or obj.get("parameters") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            return None
    if name in names and isinstance(args, dict):
        return str(name), args
    return None


def _text(result: Any) -> str:
    sc = getattr(result, "structured_content", None)
    if sc:
        return json.dumps(sc.get("result", sc) if isinstance(sc, dict) else sc, ensure_ascii=False)
    return "".join(getattr(c, "text", "") for c in result.content)


async def run(
    kp: Clarikube,
    question: str,
    model: str,
    base_url: str,
    api_key: str | None = None,
    max_steps: int = 8,
    max_tool_chars: int = 6000,
    post: Post = http_post,
    log: Callable[[str], None] = lambda _m: None,
) -> Transcript:
    tr = Transcript(question=question, model=model)
    started = time.monotonic()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    url = base_url.rstrip("/") + "/chat/completions"
    async with Client(create_server(kp)) as client:
        tools = [t for t in (await client.list_tools()).tools if t.name not in HIDDEN_TOOLS]
        names = {t.name for t in tools}
        spec = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema},
            }
            for t in tools
        ]
        messages: list[dict[str, Any]] = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": question}]
        for _ in range(max_steps):
            resp = post(url, {"model": model, "messages": messages, "tools": spec, "temperature": 0}, headers)
            usage = resp.get("usage") or {}
            tr.prompt_tokens += int(usage.get("prompt_tokens") or 0)
            tr.completion_tokens += int(usage.get("completion_tokens") or 0)
            msg = (resp.get("choices") or [{}])[0].get("message") or {}
            calls = msg.get("tool_calls") or []
            if not calls:
                inline = _inline_tool_call(msg.get("content") or "", names)
                if inline is None:
                    tr.answer = (msg.get("content") or "").strip()
                    break
                calls = [
                    {
                        "id": "inline",
                        "type": "function",
                        "function": {"name": inline[0], "arguments": json.dumps(inline[1])},
                    }
                ]
                msg = {"role": "assistant", "content": None, "tool_calls": calls}
            messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": calls})
            for call in calls:
                fn = call.get("function") or {}
                name = str(fn.get("name") or "")
                raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else dict(raw)
                except (json.JSONDecodeError, TypeError, ValueError):
                    args = {}
                t0 = time.monotonic()
                if name not in names:
                    text, ok = f"error: unknown or unavailable tool {name!r}", False
                else:
                    log(f"→ {name}({', '.join(f'{k}={v!r}' for k, v in args.items())})")
                    result = await client.call_tool(name, args)
                    ok = not getattr(result, "is_error", False)
                    text = _text(result)
                if len(text) > max_tool_chars:
                    text = text[:max_tool_chars] + f"\n…[truncated {len(text) - max_tool_chars} chars]"
                tr.steps.append(Step(name, args, ok, len(text), round(time.monotonic() - t0, 3)))
                messages.append({"role": "tool", "tool_call_id": call.get("id") or name, "name": name, "content": text})
        else:
            tr.stopped = "max_steps"
    tr.seconds = time.monotonic() - started
    return tr


def ask(kp: Clarikube, question: str, **kw: Any) -> Transcript:
    return asyncio.run(run(kp, question, **kw))
