"""Command-line entry point: run the MCP server, the Falco ingest receiver, and human-side commands."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from kubepilot.config import Settings


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str, ensure_ascii=False))


def _service() -> Any:
    from kubepilot.service import build_from_settings

    return build_from_settings(Settings.from_env())


def cmd_serve(args: argparse.Namespace) -> int:
    from kubepilot.server import create_server

    server = create_server(_service())
    if args.transport == "http":
        if args.host not in ("127.0.0.1", "localhost", "::1"):
            logging.warning("Serving MCP over HTTP on %s: put authentication/TLS in front of it.", args.host)
        server.run("streamable-http", host=args.host, port=args.port)
    else:
        server.run("stdio")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    import uvicorn

    from kubepilot.source.alerts import AlertStore, make_ingest_app

    s = Settings.from_env()
    db = s.alerts_db or (s.state_dir / "alerts.db")
    app = make_ingest_app(AlertStore(db), token=s.ingest_token)
    if not s.ingest_token:
        logging.warning("KUBEPILOT_INGEST_TOKEN not set: the Falco webhook endpoint is unauthenticated.")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    kp = _service()
    _print(kp.cluster_health(args.namespace) if not args.security else kp.security_triage(args.namespace))
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    _print(_service().diagnose_workload(args.namespace, args.name))
    return 0


def cmd_plans(args: argparse.Namespace) -> int:
    _print(_service().list_plans())
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    kp = _service()
    plan = kp._require_plans().get(args.plan_id)
    print(f"Plan {plan.id} for {plan.workload.key} — status={plan.status} risk={plan.risk} blocked={plan.blocked}")
    for line in plan.applied:
        print(f"  * {line}")
    for f in plan.files:
        print(f.diff)
    for n in plan.notes:
        print(f"NOTE: {n}")
    for r in plan.blocking_reasons:
        print(f"BLOCKED: {r}")
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    kp = _service()
    store = kp._require_plans()
    plan = store.get(args.plan_id)
    cmd_show(args)
    if not args.yes:
        answer = input(f"Approve plan {plan.id} for {plan.workload.key}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Not approved.")
            return 1
    store.approve_cli(plan.id)
    print(f"Approved {plan.id}. The agent can now call commit_plan.")
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    _service()._require_plans().reject(args.plan_id)
    print(f"Rejected {args.plan_id}.")
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Write a live cluster (or namespace) to a fixture directory, for offline analysis or bug reports."""
    from datetime import UTC, datetime

    from kubepilot.source.kube import KubeSource

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    raw = KubeSource(context=Settings.from_env().kube_context).raw_dump(args.namespace)
    (out / "meta.yaml").write_text(yaml.safe_dump({"now": datetime.now(UTC).isoformat()}))
    for attr in raw.__dataclass_fields__:
        items = getattr(raw, attr)
        if items:
            (out / f"{attr}.yaml").write_text(yaml.safe_dump({"apiVersion": "v1", "kind": "List", "items": items}))
    print(f"Captured to {out} (no Secrets are read or written).")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    p = argparse.ArgumentParser(prog="kubepilot", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the MCP server")
    s.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("ingest", help="run the Falcosidekick webhook receiver")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=2801)
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("triage", help="print cluster health (or --security triage) as JSON")
    s.add_argument("namespace", nargs="?")
    s.add_argument("--security", action="store_true")
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("diagnose", help="diagnose one workload")
    s.add_argument("namespace")
    s.add_argument("name")
    s.set_defaults(fn=cmd_diagnose)

    s = sub.add_parser("plans", help="list remediation plans")
    s.set_defaults(fn=cmd_plans)

    for name, fn, helptext in (
        ("show", cmd_show, "show a plan's diff"),
        ("approve", cmd_approve, "approve a plan (human, at a terminal)"),
        ("reject", cmd_reject, "reject a plan"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("plan_id")
        if name == "approve":
            s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
        s.set_defaults(fn=fn)

    s = sub.add_parser("capture", help="dump a live cluster to a fixture directory")
    s.add_argument("--out", required=True)
    s.add_argument("-n", "--namespace")
    s.set_defaults(fn=cmd_capture)

    args = p.parse_args(argv)
    try:
        return int(args.fn(args))
    except (KeyError, PermissionError, RuntimeError, ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
