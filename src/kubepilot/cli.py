"""Command-line entry point: run the MCP server, the Falco ingest receiver, and human-side commands."""

from __future__ import annotations

import argparse
import json
import logging
import os
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
    if not s.ingest_token:
        if os.environ.get("KUBEPILOT_INGEST_ALLOW_UNAUTHENTICATED", "").lower() not in ("1", "true", "yes"):
            print(
                "error: set KUBEPILOT_INGEST_TOKEN (Falcosidekick webhook.customHeaders:"
                " 'Authorization:Bearer <token>'), or KUBEPILOT_INGEST_ALLOW_UNAUTHENTICATED=true for throwaway labs.",
                file=sys.stderr,
            )
            return 2
        logging.warning("Running the Falco webhook endpoint WITHOUT authentication.")
    app = make_ingest_app(AlertStore(db), token=s.ingest_token)
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


def _confirm_on_tty(prompt: str) -> bool:
    """Ask a human. Refuses when there is no terminal (e.g. an AI agent running the command in a shell tool)."""
    if not sys.stdin.isatty():
        print("refusing: no interactive terminal (a human must run this command)", file=sys.stderr)
        return False
    try:
        with open("/dev/tty") as tty:
            print(prompt, end="", flush=True)
            return tty.readline().strip().lower() in ("y", "yes")
    except OSError:
        return input(prompt).strip().lower() in ("y", "yes")


def cmd_commit(args: argparse.Namespace) -> int:
    """Human-only commit path (used with `kubepilot ask` or without an MCP client)."""
    kp = _service()
    store = kp._require_plans()
    plan = store.get(args.plan_id)
    cmd_show(args)
    if not _confirm_on_tty(f"Commit plan {plan.id} for {plan.workload.key} to a new branch? [y/N] "):
        print("Not committed.")
        return 1
    done = store.commit(plan.id, None, human=True)
    status = "dry-run: nothing written (KUBEPILOT_DRY_RUN=false to commit)" if store.dry_run else done.status
    print(f"{status}; branch {done.branch} commit {done.commit or '-'}" + (f" PR {done.pr_url}" if done.pr_url else ""))
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from kubepilot import agent

    model = args.model or os.environ.get("KUBEPILOT_LLM_MODEL")
    if not model:
        print("set --model or KUBEPILOT_LLM_MODEL (e.g. qwen2.5:7b-instruct for Ollama)", file=sys.stderr)
        return 2
    base = args.base_url or os.environ.get("KUBEPILOT_LLM_BASE_URL") or "http://localhost:11434/v1"
    key = os.environ.get("KUBEPILOT_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    kp = _service()
    try:
        tr = agent.ask(
            kp,
            args.question,
            model=model,
            base_url=base,
            api_key=key,
            max_steps=args.max_steps,
            max_tool_chars=args.max_tool_chars,
            log=lambda m: print(f"\033[2m{m}\033[0m", file=sys.stderr),
        )
    except BaseException as e:
        leaf: BaseException = e
        while isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:
            leaf = leaf.exceptions[0]
        if isinstance(leaf, (RuntimeError, ValueError)):
            print(f"error: {leaf}", file=sys.stderr)
            return 2
        raise
    print(tr.answer or f"(no answer: stopped after {len(tr.steps)} tool calls, reason={tr.stopped})")
    print(
        f"\033[2m[{tr.model}: {len(tr.steps)} tool calls, {tr.prompt_tokens}+{tr.completion_tokens} tokens, "
        f"{tr.seconds:.1f}s]\033[0m",
        file=sys.stderr,
    )
    if args.transcript:
        Path(args.transcript).write_text(json.dumps(tr.to_json(), indent=2, ensure_ascii=False))
    return 0 if tr.answer else 1


def cmd_reject(args: argparse.Namespace) -> int:
    _service()._require_plans().reject(args.plan_id)
    print(f"Rejected {args.plan_id}.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Zero-setup demo on the bundled broken cluster; --setup DIR also prepares the plan/commit flow."""
    import shutil
    import subprocess

    from kubepilot import demo
    from kubepilot.config import Settings as S
    from kubepilot.service import KubePilot
    from kubepilot.source.fixture import FixtureSource

    if not args.setup:
        settings = S.from_env()
        kp = KubePilot(FixtureSource(demo.CLUSTER), _demo_settings(settings, None, None))
        health = kp.cluster_health()
        print("kubepilot demo — bundled synthetic cluster (nothing is contacted)\n")
        for i in health["reliability_issues"]:
            cause = f"\n             ↳ likely root cause: {i['likely_root_cause']}" if "likely_root_cause" in i else ""
            print(f"  [{i['severity']:>8}] {i['workload']}: {i['title']}{cause}")
        for i in health["security_incidents"]:
            print(f"  [{i['severity']:>8}] {i['workload']}: security score {i['score']}")
        for layer, label in (("edge", "Edge"), ("data", "Data systems"), ("logging", "Log pipeline")):
            rows = [c for c in health["components"] if c["layer"] == layer]
            if rows:
                print(f"\n{label}:")
            for c in rows:
                issue = f" — {c['top_issue']}" if c["top_issue"] else ""
                print(f"  [{c['status']:>8}] {c['component']}{issue}")
        if health["routing_and_certificates"]:
            print("\nRouting & TLS:")
            for r in health["routing_and_certificates"]:
                print(f"  [{r['severity']:>8}] {r['title']}")
        print("\nDetails:   kubepilot demo-diagnose shop checkout")
        print("           kubepilot demo-diagnose shop orders     (app failing because of Kafka)")
        print("Fix flow:  kubepilot demo --setup ./kubepilot-demo   (prints an MCP client config)")
        return 0

    root = Path(args.setup).expanduser().resolve()
    repo, state = root / "repo", root / "state"
    if repo.exists():
        print(f"error: {repo} already exists", file=sys.stderr)
        return 2
    shutil.copytree(demo.GITOPS_REPO, repo)
    for cmd in (
        ["init", "-q", "-b", "main"],
        ["add", "-A"],
        ["-c", "user.name=demo", "-c", "user.email=demo@local", "commit", "-qm", "demo baseline"],
    ):
        subprocess.run(["git", "-C", str(repo), *cmd], check=True)
    env = {
        "KUBEPILOT_SOURCE": "fixture",
        "KUBEPILOT_GITOPS_REPO": str(repo),
        "KUBEPILOT_STATE_DIR": str(state),
        "KUBEPILOT_DRY_RUN": "false",
    }
    src_root = Path(__file__).resolve().parents[2]
    if (src_root / "pyproject.toml").is_file():  # running from a source checkout
        command, cmd_args = "uv", ["--directory", str(src_root), "run", "kubepilot", "serve"]
    else:  # installed from PyPI
        command, cmd_args = "uvx", ["kubepilot", "serve"]
    cfg = {"mcpServers": {"kubepilot-demo": {"command": command, "args": cmd_args, "env": env}}}
    print(f"Demo GitOps repo ready at {repo}\n")
    print(
        "Claude Code:\n  claude mcp add --scope user kubepilot-demo "
        + " ".join(f"-e {k}={v}" for k, v in env.items())
        + f" -- {command} {' '.join(cmd_args)}\n"
    )
    print("Other MCP clients (mcpServers JSON):")
    _print(cfg)
    print('\nThen ask: "Why is checkout failing? Prepare a fix." and approve the diff.')
    print('Or: "Why is orders crashing?" — kubepilot traces it to the Kafka cluster and proposes the config fix.')
    return 0


def _demo_settings(settings: Settings, repo: Path | None, state: Path | None) -> Settings:
    from dataclasses import replace

    from kubepilot import demo

    return replace(
        settings,
        source="fixture",
        fixture_dir=demo.CLUSTER,
        allowlist=demo.ALLOWLIST,
        gitops_repo=repo,
        state_dir=state or settings.state_dir,
        read_logs=True,  # bundled demo logs
    )


def cmd_demo_diagnose(args: argparse.Namespace) -> int:
    from kubepilot import demo
    from kubepilot.service import KubePilot
    from kubepilot.source.fixture import FixtureSource

    kp = KubePilot(FixtureSource(demo.CLUSTER), _demo_settings(Settings.from_env(), None, None))
    _print(kp.diagnose_workload(args.namespace, args.name))
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Write a live cluster (or namespace) to a fixture directory, for offline analysis or bug reports."""
    from datetime import UTC, datetime

    from kubepilot.source.kube import KubeSource

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    from kubepilot.redact import redact_objects

    raw = KubeSource(context=Settings.from_env().kube_context).raw_dump(args.namespace)
    (out / "meta.yaml").write_text(yaml.safe_dump({"now": datetime.now(UTC).isoformat()}))
    for attr in raw.__dataclass_fields__:
        items = getattr(raw, attr)
        if items:
            doc = {"apiVersion": "v1", "kind": "List", "items": redact_objects(items)}
            (out / f"{attr}.yaml").write_text(yaml.safe_dump(doc))
    print(
        f"Captured to {out}. Secrets are never read; env values, last-applied-configuration and managedFields are "
        "redacted. Still review the files before sharing them (names, images and labels remain)."
    )
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

    s = sub.add_parser("ask", help="ask a local/OpenAI-compatible model to investigate (no MCP client needed)")
    s.add_argument("question")
    s.add_argument("--model", help="model name (env KUBEPILOT_LLM_MODEL), e.g. qwen2.5:7b-instruct")
    s.add_argument("--base-url", help="OpenAI-compatible base URL (env KUBEPILOT_LLM_BASE_URL; default Ollama)")
    s.add_argument("--max-steps", type=int, default=8)
    s.add_argument("--max-tool-chars", type=int, default=6000, help="truncate each tool result for small models")
    s.add_argument("--transcript", help="write a JSON transcript (tool calls, tokens, timings)")
    s.set_defaults(fn=cmd_ask)

    for name, fn, helptext in (
        ("show", cmd_show, "show a plan's diff"),
        ("commit", cmd_commit, "commit a plan to a new branch (human at a terminal only)"),
        ("approve", cmd_approve, "approve a plan (human, at a terminal)"),
        ("reject", cmd_reject, "reject a plan"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("plan_id")
        if name == "approve":
            s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
        s.set_defaults(fn=fn)

    s = sub.add_parser("demo", help="try kubepilot on a bundled broken cluster (no cluster needed)")
    s.add_argument("--setup", metavar="DIR", help="also create a demo GitOps repo and print an MCP config")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("demo-diagnose", help="diagnose a workload of the bundled demo cluster")
    s.add_argument("namespace")
    s.add_argument("name")
    s.set_defaults(fn=cmd_demo_diagnose)

    s = sub.add_parser("capture", help="dump a live cluster to a fixture directory")
    s.add_argument("--out", required=True)
    s.add_argument("-n", "--namespace")
    s.set_defaults(fn=cmd_capture)

    args = p.parse_args(argv)
    try:
        return int(args.fn(args))
    except BrokenPipeError:  # e.g. `kubepilot triage | head`
        sys.stderr.close()
        return 0
    except (KeyError, PermissionError, RuntimeError, ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
