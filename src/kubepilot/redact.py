"""Redaction for data that leaves the machine (``kubepilot capture``).

Kubernetes Secrets are never read, but secrets often live elsewhere in plain objects:
literal env values, the ``last-applied-configuration`` annotation (a full copy of the spec),
``managedFields``, container args, and probe/lifecycle commands.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "<redacted>"
_DROP_ANNOTATIONS = {"kubectl.kubernetes.io/last-applied-configuration"}
_SECRETISH = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)", re.I)


# A bare service address (no credentials, no query string) is kept so dependency inference still works on
# captures: "kafka:9092", "http://search.data:9200", "redis://cache.data.svc:6379/0".
_ADDRESS = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?(?:/[\w./-]*)?$", re.I)


def _env_value(name: str, value: str) -> str:
    v = value.strip()
    if _SECRETISH.search(name) or "@" in v or not _ADDRESS.match(v):
        return REDACTED
    host = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v, flags=re.I).split("/", 1)[0]
    looks_like_address = "://" in v or ":" in host or "." in host  # a lone word could be a password
    return v if looks_like_address else REDACTED


def _redact(node: Any, key: str = "") -> Any:
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            if k == "managedFields":
                continue
            if k == "annotations" and isinstance(v, dict):
                out[k] = {
                    ak: (REDACTED if _SECRETISH.search(ak) else av)
                    for ak, av in v.items()
                    if ak not in _DROP_ANNOTATIONS
                }
                continue
            if k == "env" and isinstance(v, list):
                out[k] = [
                    {**e, "value": _env_value(str(e.get("name", "")), str(e["value"]))}
                    if isinstance(e, dict) and "value" in e
                    else _redact(e)
                    for e in v
                ]
                continue
            if k in ("args", "command") and isinstance(v, list):
                out[k] = [REDACTED if _SECRETISH.search(str(a)) else a for a in v]
                continue
            out[k] = _redact(v, k)
        return out
    if isinstance(node, list):
        return [_redact(x, key) for x in node]
    return node


def redact_objects(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_redact(o) for o in items]
