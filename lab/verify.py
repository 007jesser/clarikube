"""Checks that kubemedic finds what the lab deliberately broke. Prints PASS / WARN / FAIL per check.

    uv run python lab/verify.py --phase baseline   # right after install
    uv run python lab/verify.py --phase broken     # after lab/break.sh
    uv run python lab/verify.py --phase attacked   # after lab/attack.sh
    uv run python lab/verify.py --phase fixed      # after committing + applying kubemedic's fixes
    uv run python lab/verify.py --phase data       # after lab/data.sh (optional data tier)

WARN = not wrong, just not ready yet (e.g. Trivy still scanning, CronJob not run yet).
Uses the same settings as `kubemedic serve` (KUBEMEDIC_* env vars).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kubemedic.config import Settings
from kubemedic.service import Kubemedic, build_from_settings

GREEN, YELLOW, RED, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[0m"


@dataclass
class Report:
    rows: list[tuple[str, str, str]] = field(default_factory=list)

    def add(self, status: str, check: str, detail: str = "") -> None:
        self.rows.append((status, check, detail))

    def ok(self, cond: bool, check: str, detail: str = "", warn_only: bool = False) -> bool:
        self.add("PASS" if cond else ("WARN" if warn_only else "FAIL"), check, detail)
        return cond

    def print(self) -> int:
        color = {"PASS": GREEN, "WARN": YELLOW, "FAIL": RED}
        for status, check, detail in self.rows:
            print(f"{color[status]}{status:<4}{RESET}  {check}" + (f"  — {detail}" if detail else ""))
        fails = sum(1 for r in self.rows if r[0] == "FAIL")
        warns = sum(1 for r in self.rows if r[0] == "WARN")
        print(f"\n{len(self.rows) - fails - warns} passed, {warns} warnings, {fails} failed")
        return 1 if fails else 0


def findings(kp: Kubemedic, name: str) -> list[dict[str, Any]]:
    try:
        return list(kp.diagnose_workload("shop", name)["findings"])
    except Exception as e:
        return [{"title": f"ERROR {e}", "explanation": "", "remediations": []}]


def has(fs: list[dict[str, Any]], text: str) -> dict[str, Any] | None:
    return next((f for f in fs if text.lower() in (f["title"] + " " + f["explanation"]).lower()), None)


def incident(kp: Kubemedic, ns: str, name: str) -> dict[str, Any] | None:
    for i in kp.security_triage(ns, min_score=0)["incidents"]:
        if i["workload"].endswith(f"/{ns}/{name}"):
            return dict(i)
    return None


def check_common(kp: Kubemedic, r: Report) -> None:
    health = kp.cluster_health()
    r.ok(health["source"] == "kube", "connected to a live cluster", f"source={health['source']}", warn_only=True)
    for w in health["warnings"]:
        r.add("WARN", "data source warning", w)
    r.ok(health["nodes"]["total"] >= 1 and not health["nodes"]["not_ready"], "node(s) Ready", f"{health['nodes']}")

    api = findings(kp, "api")
    f = has(api, "api-db-credentials")
    r.ok(f is not None, "api: missing Secret detected", f["title"] if f else str([x["title"] for x in api]))

    worker = findings(kp, "worker")
    f = has(worker, "unschedulable")
    r.ok(f is not None, "worker: Pending/unschedulable detected", f["explanation"][:120] if f else "")
    if f:
        r.ok(
            "can never fit" in f["explanation"],
            "worker: request larger than any node recognised",
            f["explanation"][:160],
        )

    inc = incident(kp, "shop", "payment-api")
    r.ok(inc is not None, "payment-api: security incident exists")
    if inc:
        sig = " ".join(inc["signals"])
        r.ok("secrets" in sig, "payment-api: ServiceAccount secret access flagged")
        r.ok("NetworkPolicy" in sig, "payment-api: missing NetworkPolicy flagged")
        r.ok("root" in sig, "payment-api: runs as root flagged")
        r.ok(
            "CVE" in sig,
            "payment-api: CVEs from Trivy",
            sig[:160]
            if "CVE" in sig
            else "no VulnerabilityReport yet — Trivy may still be scanning (kubectl get vulnerabilityreports -A)",
            warn_only=True,
        )


def check_baseline(kp: Kubemedic, r: Report) -> None:
    for name in ("checkout", "frontend"):
        fs = [f for f in findings(kp, name) if f.get("severity") in ("high", "critical", "medium")]
        r.ok(not fs, f"{name}: healthy at baseline", "; ".join(f["title"] for f in fs))


def check_broken(kp: Kubemedic, r: Report) -> None:
    fs = findings(kp, "checkout")
    f = has(fs, "OOMKilled")
    r.ok(f is not None, "checkout: OOMKilled detected", "wait for at least one restart" if not f else "")
    if f:
        r.ok(
            "lowered the memory limit from 512Mi to 128Mi" in f["explanation"],
            "checkout: OOM correlated with the bad rollout",
            f["explanation"][-160:],
        )
        r.ok(any(h["kind"] == "set-memory-limit" for h in f["remediations"]), "checkout: memory fix proposed")
    fs = findings(kp, "frontend")
    f = has(fs, "Image pull")
    r.ok(f is not None, "frontend: image pull failure detected")
    if f:
        r.ok("does not exist" in f["explanation"], "frontend: cause = tag not found", f["explanation"][:140])
        r.ok(any(h["kind"] == "set-image" for h in f["remediations"]), "frontend: revert to previous image proposed")


def check_attacked(kp: Kubemedic, r: Report, settings: Settings) -> None:
    if settings.alerts_db is None or not Path(settings.alerts_db).exists():
        r.add("FAIL", "Falco alerts DB present", f"{settings.alerts_db} missing — is `make lab-ingest` running?")
        return
    inc = incident(kp, "shop", "payment-api")
    sig = " ".join(inc["signals"]) if inc else ""
    r.ok(
        "Falco" in sig,
        "payment-api: Falco runtime alerts mapped to the workload",
        "no alerts mapped — check Falco pod metadata (docs/TESTING.md#falco)" if "Falco" not in sig else sig[:120],
    )
    if inc:
        r.ok(inc["severity"] in ("high", "critical"), "payment-api: rated high/critical", f"score={inc['score']}")
    backup = incident(kp, "batch", "backup")
    if backup is None or backup["suppressed_alerts"] == 0:
        r.add(
            "WARN",
            "backup: Falco noise suppressed by allowlist",
            "no suppressed alerts yet — CronJob runs every 5 min; check alerts arrive from batch",
        )
    else:
        r.ok(
            not any("Falco" in s for s in backup["signals"]),
            "backup: Falco noise suppressed by allowlist",
            f"{backup['suppressed_alerts']} suppressed",
        )


def check_fixed(kp: Kubemedic, r: Report) -> None:
    for name, text in (("checkout", "OOMKilled"), ("frontend", "Image pull")):
        r.ok(
            has(findings(kp, name), text) is None,
            f"{name}: problem gone after fix",
            "pods may need a minute to roll" if has(findings(kp, name), text) else "",
        )


def check_data(kp: Kubemedic, r: Report) -> None:
    comps = {c["name"]: c for c in kp.list_components("data")["components"]}
    for name in ("cache", "queue", "search"):
        r.ok(
            name in comps,
            f"data/{name}: detected as a component",
            comps.get(name, {}).get("component", ""),
            warn_only=name == "search",
        )

    def titles(name: str) -> str:
        try:
            return " | ".join(f["title"] for f in kp.diagnose_component("data", name)["findings"])
        except Exception as e:
            return f"ERROR {e}"

    t = titles("cache")
    r.ok("without a password" in t or "protected mode" in t.lower(), "redis: no auth detected", t[:160])
    r.ok("reachable from outside" in t, "redis: NodePort exposure detected", t[:160])
    t = titles("queue")
    r.ok("even number" in t, "rabbitmq: even member count detected", t[:160])
    r.ok("PodDisruptionBudget" in t, "rabbitmq: missing PDB detected", t[:160])
    if "search" in comps:
        t = titles("search")
        r.ok("JVM heap" in t, "opensearch: heap vs limit detected", t[:160])
        fs = findings(kp, "reports")
        f = has(fs, "Likely root cause: OpenSearch")
        r.ok(
            f is not None,
            "shop/reports: crash blamed on OpenSearch",
            "; ".join(x["title"] for x in fs)[:160],
            warn_only=True,
        )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["baseline", "broken", "attacked", "fixed", "data"], default="baseline")
    ap.add_argument("--json", action="store_true", help="also dump the raw cluster_health output")
    args = ap.parse_args()
    settings = Settings.from_env()
    kp = build_from_settings(settings)
    r = Report()
    check_common(kp, r)
    {
        "baseline": lambda: check_baseline(kp, r),
        "broken": lambda: check_broken(kp, r),
        "attacked": lambda: check_attacked(kp, r, settings),
        "fixed": lambda: check_fixed(kp, r),
        "data": lambda: check_data(kp, r),
    }[args.phase]()
    if args.json:
        print(json.dumps(kp.cluster_health(), indent=2, ensure_ascii=False))
    print(f"\nkubemedic lab verification — phase: {args.phase}\n")
    return r.print()


if __name__ == "__main__":
    sys.exit(main())
