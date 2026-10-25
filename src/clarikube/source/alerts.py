"""Falco alert storage (SQLite) and the Falcosidekick webhook receiver.

Falcosidekick's ``webhook`` output POSTs each Falco event as JSON. We normalize and store it
so tools can query a time window without depending on Falco's own retention.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from clarikube import normalize
from clarikube.models import FalcoAlert, FiringAlert

MAX_BODY_BYTES = 256 * 1024
MAX_OUTPUT_CHARS = 4000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS falco_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    rule TEXT NOT NULL,
    priority TEXT NOT NULL,
    namespace TEXT,
    pod TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_falco_time ON falco_alerts(time);
CREATE TABLE IF NOT EXISTS prom_alerts (
    fingerprint TEXT PRIMARY KEY,
    updated TEXT NOT NULL,
    status TEXT NOT NULL,
    namespace TEXT,
    payload TEXT NOT NULL
);
"""
MAX_ALERT_SUMMARY = 500


class AlertStore:
    def __init__(self, path: str | Path, retention: timedelta = timedelta(days=7)) -> None:
        self.path = str(path)
        self.retention = retention
        self._lock = threading.Lock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(_SCHEMA)

    def add_raw(self, raw: dict[str, Any]) -> FalcoAlert:
        alert = normalize.falco_alert(raw)
        alert = alert.model_copy(update={"output": alert.output[:MAX_OUTPUT_CHARS]})
        self.add(alert)
        return alert

    def add(self, alert: FalcoAlert) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO falco_alerts(time, rule, priority, namespace, pod, payload) VALUES (?,?,?,?,?,?)",
                (
                    alert.time.isoformat(),
                    alert.rule,
                    alert.priority,
                    alert.namespace,
                    alert.pod,
                    alert.model_dump_json(),
                ),
            )
            self._db.commit()

    def add_many(self, alerts: Iterable[FalcoAlert]) -> None:
        for a in alerts:
            self.add(a)

    def since(self, start: datetime, namespace: str | None = None) -> list[FalcoAlert]:
        q = "SELECT payload FROM falco_alerts WHERE time >= ?"
        args: list[Any] = [start.isoformat()]
        if namespace:
            q += " AND namespace = ?"
            args.append(namespace)
        q += " ORDER BY time"
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [FalcoAlert.model_validate_json(r[0]) for r in rows]

    # ---------------------------------------------------------------- Prometheus alerts (Alertmanager webhook)

    def upsert_prometheus(self, raw: dict[str, Any], now: datetime) -> FiringAlert:
        """Alertmanager re-sends active alerts; keep the latest state per fingerprint (resolved ones too)."""
        alert = normalize.firing_alert(raw)
        key = alert.fingerprint or f"{alert.name}|{sorted(alert.labels.items())}"
        with self._lock:
            self._db.execute(
                "INSERT INTO prom_alerts(fingerprint, updated, status, namespace, payload) VALUES (?,?,?,?,?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET updated=excluded.updated, status=excluded.status, "
                "namespace=excluded.namespace, payload=excluded.payload",
                (key, now.isoformat(), alert.status, alert.namespace, alert.model_dump_json()),
            )
            self._db.commit()
        return alert

    def firing(self, since: datetime, namespace: str | None = None) -> list[FiringAlert]:
        q = "SELECT payload FROM prom_alerts WHERE status = 'firing' AND updated >= ?"
        args: list[Any] = [since.isoformat()]
        if namespace:
            q += " AND namespace = ?"
            args.append(namespace)
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [FiringAlert.model_validate_json(r[0]) for r in rows]

    def prune(self, now: datetime) -> int:
        with self._lock:
            cur = self._db.execute("DELETE FROM falco_alerts WHERE time < ?", ((now - self.retention).isoformat(),))
            self._db.commit()
            return cur.rowcount


def make_ingest_app(store: AlertStore, token: str | None = None) -> Any:
    """Starlette app exposing ``POST /falco`` for Falcosidekick's webhook output.

    If ``token`` is set, requests must carry ``Authorization: Bearer <token>``
    (configure via Falcosidekick ``webhook.customHeaders``).
    """
    import hmac

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, PlainTextResponse
    from starlette.routing import Route

    async def falco(request: Request) -> JSONResponse | PlainTextResponse:
        if token:
            given = request.headers.get("authorization", "")
            if not hmac.compare_digest(given, f"Bearer {token}"):
                return PlainTextResponse("unauthorized", status_code=401)
        declared = request.headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
            return PlainTextResponse("payload too large", status_code=413)
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():  # cap memory even if Content-Length lies or is absent
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return PlainTextResponse("payload too large", status_code=413)
            chunks.append(chunk)
        body = b"".join(chunks)
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return PlainTextResponse("invalid json", status_code=400)
        items = data if isinstance(data, list) else [data]
        stored = 0
        for item in items:
            if isinstance(item, dict) and item.get("rule"):
                store.add_raw(item)
                stored += 1
        return JSONResponse({"stored": stored})

    async def alertmanager(request: Request) -> JSONResponse | PlainTextResponse:
        """Alertmanager webhook_config receiver (payload version 4)."""
        from datetime import UTC
        from datetime import datetime as dt

        if token:
            given = request.headers.get("authorization", "")
            if not hmac.compare_digest(given, f"Bearer {token}"):
                return PlainTextResponse("unauthorized", status_code=401)
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return PlainTextResponse("payload too large", status_code=413)
            chunks.append(chunk)
        try:
            data = json.loads(b"".join(chunks))
        except json.JSONDecodeError:
            return PlainTextResponse("invalid json", status_code=400)
        stored = 0
        now = dt.now(UTC)
        for item in (data.get("alerts") or []) if isinstance(data, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("labels"), dict):
                store.upsert_prometheus(item, now)
                stored += 1
        return JSONResponse({"stored": stored})

    async def healthz(_: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return Starlette(
        routes=[
            Route("/falco", falco, methods=["POST"]),
            Route("/alertmanager", alertmanager, methods=["POST"]),
            Route("/healthz", healthz),
        ]
    )
