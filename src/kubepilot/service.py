"""Application service: wires sources, engines and the change pipeline together.

Every public method returns plain, JSON-serialisable, *sanitized* data ready for a model.
The MCP layer (`server.py`) and the CLI are thin adapters over this class.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from kubepilot import remediation
from kubepilot.changes import ChangePlan, PlanStore
from kubepilot.config import Settings
from kubepilot.engine import diagnose, rbac, security, selectors
from kubepilot.engine.allowlist import Allowlist
from kubepilot.models import Evidence, Finding, RemediationHint, SecurityIncident, Severity, WorkloadRef
from kubepilot.sanitize import clean, k8s_name
from kubepilot.source.base import ClusterSource, Snapshot

MAX_ITEMS = 25


class NotFound(Exception):
    pass


def _ev(e: Evidence) -> dict[str, Any]:
    d: dict[str, Any] = {"source": e.source, "detail": clean(e.detail, 500)}
    if e.at:
        d["at"] = e.at.isoformat()
    return d


def _hint(h: RemediationHint) -> dict[str, Any]:
    return {
        "kind": h.kind,
        "summary": clean(h.summary, 300),
        "automatable": h.kind in remediation.AUTOMATABLE,
    }


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "workload": f.workload.key,
        "category": f.category,
        "severity": f.severity.label,
        "title": clean(f.title, 200),
        "explanation": clean(f.explanation, 800),
        "evidence": [_ev(e) for e in f.evidence[:8]],
        "remediations": [_hint(h) for h in f.remediations],
    }


def incident_dict(i: SecurityIncident) -> dict[str, Any]:
    return {
        "id": i.id,
        "workload": i.workload.key,
        "score": i.score,
        "severity": i.severity.label,
        "summary": clean(i.summary, 400),
        "signals": [clean(s, 200) for s in i.signals],
        "evidence": [_ev(e) for e in i.evidence[:10]],
        "suppressed_alerts": i.suppressed_alerts,
        "remediations": [_hint(h) for h in i.remediations],
    }


class KubePilot:
    def __init__(self, source: ClusterSource, settings: Settings) -> None:
        self.source = source
        self.settings = settings
        self.allowlist = Allowlist.load(settings.allowlist)
        self.plans: PlanStore | None = None
        if settings.gitops_repo:
            self.plans = PlanStore(
                settings.gitops_repo,
                settings.state_dir,
                ttl=settings.plan_ttl,
                approval_mode=settings.approval_mode,
                dry_run=settings.dry_run,
                push=settings.push,
            )

    # ------------------------------------------------------------ helpers

    def _snap(self, namespace: str | None) -> Snapshot:
        return self.source.snapshot(k8s_name(namespace) if namespace else None)

    def _workload(self, snap: Snapshot, namespace: str, name: str) -> WorkloadRef:
        wl = snap.find_workload(k8s_name(namespace), k8s_name(name))
        if wl is None:
            raise NotFound(f"no workload or pod named {name!r} in namespace {namespace!r}")
        return wl

    def _meta(self, snap: Snapshot) -> dict[str, Any]:
        return {"source": self.source.name, "as_of": snap.now.isoformat(), "warnings": snap.warnings}

    # ------------------------------------------------------------ read tools

    def cluster_health(self, namespace: str | None = None) -> dict[str, Any]:
        snap = self._snap(namespace)
        findings = diagnose.diagnose_all(snap, min_severity=Severity.MEDIUM)
        incidents = [i for i in security.triage(snap, self.allowlist) if i.score >= 45]
        unhealthy_nodes = [n.name for n in snap.nodes if not n.ready]
        return {
            **self._meta(snap),
            "workloads": len(snap.workloads()),
            "pods": len(snap.pods),
            "nodes": {"total": len(snap.nodes), "not_ready": unhealthy_nodes},
            "reliability_issues": [
                {"workload": f.workload.key, "severity": f.severity.label, "title": clean(f.title, 160)}
                for f in findings[:MAX_ITEMS]
            ],
            "security_incidents": [
                {
                    "workload": i.workload.key,
                    "score": i.score,
                    "severity": i.severity.label,
                    "summary": clean(i.summary, 240),
                }
                for i in incidents[:MAX_ITEMS]
            ],
            "next_steps": "Use diagnose_workload or investigate_security for details on any item.",
        }

    def diagnose_workload(self, namespace: str, name: str, include_hygiene: bool = True) -> dict[str, Any]:
        snap = self._snap(namespace)
        wl = self._workload(snap, namespace, name)
        findings = diagnose.diagnose_workload(snap, wl, include_hygiene=include_hygiene)
        pods = snap.pods_of(wl)
        lr = diagnose.latest_rollout(snap, wl)
        rollout: dict[str, Any] | None = None
        if lr:
            cur, prev = lr
            rollout = {
                "current_revision": cur.revision,
                "rolled_out_at": cur.created_at.isoformat() if cur.created_at else None,
                "changes_vs_previous": [clean(c, 200) for c in diagnose.template_diff(prev, cur)] if prev else [],
            }
        return {
            **self._meta(snap),
            "workload": wl.key,
            "status": "healthy" if not any(f.severity >= Severity.MEDIUM for f in findings) else "unhealthy",
            "pods": [
                {
                    "name": p.name,
                    "phase": p.phase,
                    "node": p.node,
                    "containers": [
                        {
                            "name": c.name,
                            "ready": c.ready,
                            "restarts": c.restart_count,
                            "state": c.state.state,
                            "reason": clean(c.state.reason, 80) or None,
                            "last_termination": clean(c.last_state.reason, 80) or None,
                        }
                        for c in p.app_containers
                    ],
                }
                for p in pods[:10]
            ],
            "latest_rollout": rollout,
            "findings": [finding_dict(f) for f in findings],
        }

    def find_problems(self, namespace: str | None = None, min_severity: str = "medium") -> dict[str, Any]:
        snap = self._snap(namespace)
        sev = Severity[min_severity.upper()]
        findings = diagnose.diagnose_all(snap, include_hygiene=sev <= Severity.LOW, min_severity=sev)
        return {
            **self._meta(snap),
            "count": len(findings),
            "findings": [finding_dict(f) for f in findings[:MAX_ITEMS]],
        }

    def security_triage(
        self, namespace: str | None = None, since_hours: int | None = None, min_score: int = 10
    ) -> dict[str, Any]:
        snap = self._snap(namespace)
        since = timedelta(hours=since_hours) if since_hours else None
        incidents = security.triage(snap, self.allowlist, since=since, min_score=min_score)
        return {
            **self._meta(snap),
            "scoring": "Explicit points per signal (see docs/scoring.md); x1.5 when runtime alerts "
            "co-occur with exploitable CVEs or excessive exposure. 70+ critical, 45+ high, 25+ medium.",
            "incidents": [incident_dict(i) for i in incidents[:MAX_ITEMS]],
            "suppressed_by_allowlist": sum(i.suppressed_alerts for i in incidents),
        }

    def investigate_security(self, namespace: str, name: str) -> dict[str, Any]:
        snap = self._snap(namespace)
        wl = self._workload(snap, namespace, name)
        inc = next((i for i in security.triage(snap, self.allowlist) if i.workload == wl), None)
        pods = snap.pods_of(wl)
        exposure: dict[str, Any] = {}
        if pods:
            p = pods[0]
            grants = rbac.grants_for(p.namespace, p.service_account, snap.roles, snap.bindings)
            exposure = {
                "service_account": p.service_account,
                "token_automounted": p.automount_sa_token,
                "risky_permissions": [
                    {"permission": r.description, "via": r.via} for r in rbac.risky_permissions(grants)
                ],
                "ingress_policies": [n.name for n in selectors.covering_policies(p, snap.network_policies, "Ingress")],
                "egress_policies": [n.name for n in selectors.covering_policies(p, snap.network_policies, "Egress")],
                "containers": [
                    {
                        "name": c.name,
                        "image": clean(c.image, 200),
                        "privileged": c.security.privileged,
                        "may_run_as_root": c.security.may_run_as_root,
                        "allow_privilege_escalation": c.security.allow_privilege_escalation,
                        "capabilities_add": c.security.capabilities_add,
                    }
                    for c in p.app_containers
                ],
                "host_access": {
                    "hostNetwork": p.host_network,
                    "hostPID": p.host_pid,
                    "hostPath": [v.source for v in p.volumes if v.kind == "hostPath"],
                },
            }
        vulns = [
            {
                "id": v.id,
                "severity": v.severity.label,
                "package": clean(v.package, 80),
                "installed": clean(v.installed_version, 40),
                "fixed": clean(v.fixed_version, 40) or None,
                "title": clean(v.title, 160),
            }
            for r in snap.vulnerability_reports
            if r.workload == wl
            for v in sorted(r.vulnerabilities, key=lambda v: -v.severity)
            if v.severity >= Severity.HIGH
        ]
        return {
            **self._meta(snap),
            "workload": wl.key,
            "incident": incident_dict(inc) if inc else None,
            "exposure": exposure,
            "high_and_critical_vulnerabilities": vulns[:MAX_ITEMS],
        }

    def recent_events(self, namespace: str, name: str | None = None, warnings_only: bool = True) -> dict[str, Any]:
        snap = self._snap(namespace)
        events = snap.events
        if name:
            events = snap.events_for(self._workload(snap, namespace, name))
        if warnings_only:
            events = [e for e in events if e.type == "Warning"]
        events = sorted(events, key=lambda e: e.last_seen or snap.now, reverse=True)
        return {
            **self._meta(snap),
            "events": [
                {
                    "type": e.type,
                    "reason": clean(e.reason, 60),
                    "object": f"{e.involved_kind}/{clean(e.involved_name, 120)}",
                    "count": e.count,
                    "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                    "message": clean(e.message, 300),
                }
                for e in events[:MAX_ITEMS]
            ],
        }

    # ------------------------------------------------------------ change pipeline

    def _require_plans(self) -> PlanStore:
        if self.plans is None:
            raise RuntimeError("GitOps change flow disabled: set KUBEPILOT_GITOPS_REPO to a local clone")
        return self.plans

    def plan_remediation(self, namespace: str, name: str, kinds: list[str] | None = None) -> dict[str, Any]:
        store = self._require_plans()
        snap = self._snap(namespace)
        wl = self._workload(snap, namespace, name)
        findings = diagnose.diagnose_workload(snap, wl)
        inc = next((i for i in security.triage(snap, self.allowlist) if i.workload == wl), None)
        reliability: dict[str, RemediationHint] = {}
        for f in findings:
            for h in f.remediations:
                reliability.setdefault(h.kind, h)
        sec: dict[str, RemediationHint] = {h.kind: h for h in inc.remediations} if inc else {}
        hints = {**sec, **reliability}
        if kinds:
            unknown = set(kinds) - set(hints)
            if unknown:
                raise ValueError(f"not applicable to {wl.key}: {sorted(unknown)}; available: {sorted(hints) or 'none'}")
            selected = [hints[k] for k in kinds]
        else:
            # One concern per PR: reliability fixes first; otherwise security hardening.
            # Opt-in only: rollback-template (supersedes field edits) and isolate-workload (cuts traffic).
            pool = reliability if findings else sec
            selected = [h for h in pool.values() if h.kind not in ("rollback-template", "isolate-workload")]
        evidence = "; ".join(clean(f.explanation, 300) for f in findings[:2])
        if inc:
            evidence = (evidence + " | " if evidence else "") + clean(inc.summary, 300)
        result = remediation.build(store.repo, snap, wl, selected)
        plan, token = store.create(wl, result, evidence or "operator request")
        out = plan.public()
        out["approval_token"] = token
        out["available_kinds"] = sorted(hints)
        out["instructions"] = (
            "Show the diff, notes and policy results to the human and get explicit approval before calling "
            "commit_plan. Nothing touches the cluster: commit_plan creates a Git branch for review."
            + (
                " Approval mode is 'cli': the human must also run `kubepilot approve <id>`."
                if store.approval_mode == "cli"
                else ""
            )
        )
        return out

    def commit_plan(self, plan_id: str, approval_token: str) -> dict[str, Any]:
        store = self._require_plans()
        plan: ChangePlan = store.commit(plan_id, approval_token)
        return {
            "plan_id": plan.id,
            "status": "dry-run (nothing written; set KUBEPILOT_DRY_RUN=false to commit)"
            if store.dry_run
            else plan.status,
            "branch": plan.branch,
            "commit": plan.commit,
            "pr_url": plan.pr_url,
            "next": "Open/merge the PR; your GitOps controller applies it. Roll back with `git revert`.",
        }

    def list_plans(self) -> dict[str, Any]:
        store = self._require_plans()
        return {
            "plans": [
                {
                    "id": p.id,
                    "workload": p.workload.key,
                    "status": p.status,
                    "blocked": p.blocked,
                    "created_at": p.created_at.isoformat(),
                    "branch": p.branch,
                }
                for p in store.all_plans()[:MAX_ITEMS]
            ]
        }

    def change_history(self, limit: int = 20) -> dict[str, Any]:
        return {"events": self._require_plans().history(limit)}


def build_from_settings(settings: Settings) -> KubePilot:
    source: ClusterSource
    if settings.source == "fixture":
        from kubepilot.source.fixture import FixtureSource

        directory = settings.fixture_dir or Path(__file__).resolve().parents[2] / "examples" / "demo-cluster"
        source = FixtureSource(directory)
    else:
        from kubepilot.source.alerts import AlertStore
        from kubepilot.source.kube import KubeSource

        alerts = AlertStore(settings.alerts_db) if settings.alerts_db else None
        source = KubeSource(context=settings.kube_context, alerts=alerts, falco_window=settings.falco_window)
    return KubePilot(source, settings)
