"""Launch report: run clarikube against the live lab and measure what it finds, how fast, and how much context it
saves compared with the raw kubectl output an agent would otherwise read.

    make lab-report            # writes lab-report-<date>/{report.md, report.json, fixture/}

Nothing is changed in the cluster. The fixture is a redacted capture (no Secrets, env values redacted) so real
quirks can become tests. Review the folder before sharing it.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clarikube.config import Settings
from clarikube.service import Clarikube, build_from_settings

CHARS_PER_TOKEN = 4  # rough average for English/JSON with modern tokenizers


def tokens(obj: Any) -> int:
    text = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return max(1, len(text) // CHARS_PER_TOKEN)


def kubectl(*args: str, timeout: int = 60) -> str:
    try:
        r = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"<error: {e}>"
    return r.stdout + r.stderr


def timed(fn: Any, *a: Any, **kw: Any) -> tuple[Any, float, str | None]:
    t0 = time.perf_counter()
    try:
        out = fn(*a, **kw)
        err = None
    except Exception as e:  # a report must survive one failing tool
        out, err = None, f"{type(e).__name__}: {e}"
    return out, round(time.perf_counter() - t0, 2), err


def raw_baseline(failing: list[tuple[str, str, str]]) -> dict[str, int]:
    """What a kubectl-only agent typically reads to get to the same answers."""
    parts = {
        "kubectl get pods -A -o yaml": kubectl("get", "pods", "-A", "-o", "yaml"),
        "kubectl get events -A": kubectl("get", "events", "-A"),
        "kubectl get deploy,sts,ds,svc,ingress -A -o yaml": kubectl(
            "get", "deploy,sts,ds,svc,ingress", "-A", "-o", "yaml"
        ),
    }
    for ns, pod, container in failing[:5]:
        parts[f"kubectl describe pod {ns}/{pod}"] = kubectl("describe", "pod", "-n", ns, pod)
        parts[f"kubectl logs --previous {ns}/{pod}"] = kubectl(
            "logs", "-n", ns, pod, "-c", container, "--previous", "--tail=200"
        )
    return {k: tokens(v) for k, v in parts.items()}


def main() -> int:
    settings = Settings.from_env()
    kp: Clarikube = build_from_settings(settings)
    out_dir = Path(f"lab-report-{datetime.now(UTC):%Y%m%d-%H%M}")
    out_dir.mkdir(exist_ok=True)
    rep: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {"python": sys.version.split()[0], "os": platform.platform()},
        "kubectl_version": kubectl("version", "-o", "json")[:2000],
        "tools": {},
    }

    health, t, err = timed(kp.cluster_health)
    rep["tools"]["cluster_health"] = {"seconds": t, "tokens": tokens(health or {}), "error": err}
    health = health or {}
    rep["cluster"] = {
        "source": health.get("source"),
        "nodes": health.get("nodes"),
        "workloads": health.get("workloads"),
        "pods": health.get("pods"),
        "warnings": health.get("warnings"),
    }
    # second call: snapshot cache warm (what an agent sees on follow-up calls)
    _, t2, _ = timed(kp.cluster_health)
    rep["tools"]["cluster_health_cached"] = {"seconds": t2}

    comps, t, err = timed(kp.list_components)
    rep["tools"]["list_components"] = {"seconds": t, "tokens": tokens(comps or {}), "error": err}
    rep["components"] = [
        {k: c.get(k) for k in ("component", "layer", "managed_by", "status", "members", "issues")}
        for c in (comps or {}).get("components", [])
    ]

    problems, t, err = timed(kp.find_problems, None, "medium")
    rep["tools"]["find_problems"] = {"seconds": t, "tokens": tokens(problems or {}), "error": err}
    findings = (problems or {}).get("findings", [])
    rep["findings_by_severity"] = {}
    for f in findings:
        rep["findings_by_severity"][f["severity"]] = rep["findings_by_severity"].get(f["severity"], 0) + 1
    rep["top_findings"] = [
        {"workload": f["workload"], "severity": f["severity"], "title": f["title"]} for f in findings[:25]
    ]
    rep["platform_issues"] = health.get("platform_issues", [])
    rep["capacity"] = health.get("capacity")

    sec, t, err = timed(kp.security_triage)
    rep["tools"]["security_triage"] = {"seconds": t, "tokens": tokens(sec or {}), "error": err}
    rep["security_top"] = [
        {"workload": i["workload"], "score": i["score"], "severity": i["severity"]}
        for i in (sec or {}).get("incidents", [])[:10]
    ]

    # diagnose each unhealthy workload, like an agent would after cluster_health
    failing_pods: list[tuple[str, str, str]] = []
    diagnoses = []
    seen_wl: list[str] = []
    for row in health.get("reliability_issues", []):
        if row["workload"] not in seen_wl:
            seen_wl.append(row["workload"])
    for key in seen_wl[:12]:
        row = {"workload": key}
        _kind, ns, name = row["workload"].split("/", 2)
        d, t, err = timed(kp.diagnose_workload, ns, name)
        diagnoses.append(
            {
                "workload": row["workload"],
                "seconds": t,
                "tokens": tokens(d or {}),
                "error": err,
                "first_finding": (d or {}).get("findings", [{}])[0].get("title") if d else None,
                "log_signals": [s["kind"] for s in (d or {}).get("log_signals", [])],
            }
        )
        for p in (d or {}).get("pods", [])[:1]:
            bad = next((c for c in p["containers"] if not c["ready"]), None)
            if bad:
                failing_pods.append((ns, p["name"], bad["name"]))
    rep["diagnoses"] = diagnoses

    kp_total = sum(v.get("tokens", 0) for k, v in rep["tools"].items() if k != "cluster_health_cached")
    kp_total += sum(d["tokens"] for d in diagnoses)
    raw = raw_baseline(failing_pods)
    rep["context_comparison"] = {
        "clarikube_tokens": kp_total,
        "raw_kubectl_tokens": sum(raw.values()),
        "raw_breakdown": raw,
        "ratio": round(sum(raw.values()) / kp_total, 1) if kp_total else None,
        "note": "Approximate (chars/4). clarikube output is pre-correlated findings; raw is what a kubectl-only "
        "agent would read to reach the same conclusions (and it still has to do the correlation itself).",
    }

    (out_dir / "report.json").write_text(json.dumps(rep, indent=2, ensure_ascii=False))
    (out_dir / "report.md").write_text(render(rep))
    cap = subprocess.run(
        [sys.executable, "-m", "clarikube.cli", "capture", "--out", str(out_dir / "fixture")],
        capture_output=True,
        text=True,
    )
    print(render(rep))
    print(
        f"\nSaved to {out_dir}/ (report.md, report.json, fixture/). capture: "
        f"{'ok' if cap.returncode == 0 else cap.stderr.strip()[:200]}"
    )
    print("Review the folder, then zip it and send it back: zip -r clarikube-lab-report.zip " + str(out_dir))
    return 0


def render(rep: dict[str, Any]) -> str:
    c = rep.get("cluster", {})
    nodes = c.get("nodes") or {}
    cc = rep.get("context_comparison", {})
    lines = [
        f"# clarikube lab report ({rep['generated_at'][:16]})",
        "",
        f"Cluster: {nodes.get('total')} node(s), not ready: {nodes.get('not_ready')} · "
        f"{c.get('workloads')} workloads · {c.get('pods')} pods",
        "",
        "## Speed and context",
        "| tool | seconds | ~tokens | error |",
        "|---|---|---|---|",
    ]
    for name, v in rep["tools"].items():
        lines.append(f"| {name} | {v.get('seconds')} | {v.get('tokens', '')} | {v.get('error') or ''} |")
    for d in rep.get("diagnoses", []):
        lines.append(f"| diagnose {d['workload']} | {d['seconds']} | {d['tokens']} | {d['error'] or ''} |")
    lines += [
        "",
        f"**Context: clarikube {cc.get('clarikube_tokens')} tokens vs raw kubectl {cc.get('raw_kubectl_tokens')} "
        f"tokens (~{cc.get('ratio')}x less), already correlated.**",
        "",
        "## Components detected",
        *[
            f"- [{x['status']}] {x['component']} ({x['layer']}, {x['managed_by']}) {x['members']}"
            for x in rep.get("components", [])
        ],
        "",
        "## Findings by severity",
        json.dumps(rep.get("findings_by_severity", {})),
        "",
        "## Root causes (first finding per broken workload)",
        *[
            f"- {d['workload']}: {d['first_finding']}"
            + (f"  (logs: {', '.join(d['log_signals'])})" if d["log_signals"] else "")
            for d in rep.get("diagnoses", [])
        ],
        "",
        "## Platform issues",
        *[f"- [{p['severity']}] {p['area']}: {p['title']}" for p in rep.get("platform_issues", [])[:30]],
        "",
        "## Warnings (data sources)",
        *[f"- {w}" for w in (c.get("warnings") or [])],
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
