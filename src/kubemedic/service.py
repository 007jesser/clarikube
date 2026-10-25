"""Application service: wires sources, engines and the change pipeline together.

Every public method returns plain, JSON-serialisable, *sanitized* data ready for a model.
The MCP layer (`server.py`) and the CLI are thin adapters over this class.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from kubemedic import remediation
from kubemedic.changes import ChangePlan, PlanStore, merge_state, revert_changes
from kubemedic.config import Settings
from kubemedic.engine import components, dependencies, diagnose, layers, logsig, ops, rbac, security, selectors, usage
from kubemedic.engine.allowlist import Allowlist
from kubemedic.engine.components import Component
from kubemedic.engine.dependencies import Edge
from kubemedic.engine.logsig import LogSignal
from kubemedic.models import Evidence, Finding, RemediationHint, SecurityIncident, Severity, WorkloadRef
from kubemedic.remediation import RemediationResult
from kubemedic.sanitize import clean, k8s_name
from kubemedic.source.base import ClusterSource, Snapshot, read_logs

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


_AREAS = {
    "Ingress": "routing",
    "HTTPRoute": "routing",
    "Gateway": "routing",
    "IngressRoute": "routing",
    "Service": "routing",
    "Certificate": "tls",
    "Application": "gitops",
    "Kustomization": "gitops",
    "HelmRelease": "gitops",
    "GitRepository": "gitops",
    "HelmRepository": "gitops",
    "OCIRepository": "gitops",
    "ExternalSecret": "secrets",
    "SecretStore": "secrets",
    "ClusterSecretStore": "secrets",
    "SealedSecret": "secrets",
    "ScaledObject": "autoscaling",
    "ScaledJob": "autoscaling",
    "NodePool": "autoscaling",
    "NodeClaim": "autoscaling",
    "PersistentVolumeClaim": "storage",
    "StorageClass": "storage",
    "Volume": "storage",
    "CephCluster": "storage",
    "ClusterPolicy": "policy",
    "Policy": "policy",
    "Backup": "backup",
    "Schedule": "backup",
    "BackupStorageLocation": "backup",
    "Velero": "backup",
    "Prometheus": "monitoring",
    "Alertmanager": "monitoring",
    "Node": "nodes",
}


def _area(f: Finding) -> str:
    t = f.title
    if t.startswith("Alert firing"):
        return "alerts"
    if t.startswith(("HPA ", "Cluster Autoscaler")):
        return "autoscaling"
    if "policy" in t:
        return "policy"
    if "sidecar" in t:
        return "mesh"
    if "memory limit (OOM risk)" in t or "CPU limit" in t or " requests " in t:
        return "capacity"
    return _AREAS.get(f.workload.kind, "workloads")


_MULTI_KINDS = {"set-fluentbit-option"}  # several independent edits of the same kind can apply at once


def _unique(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    return list(seen.values())


def _hint_key(h: RemediationHint) -> str:
    return f"{h.kind}:{h.params.get('key', '')}" if h.kind in _MULTI_KINDS else h.kind


def _signal(s: LogSignal) -> dict[str, Any]:
    return {"kind": s.kind, "summary": s.summary, "excerpt": clean(s.excerpt, 200)}


class Analysis:
    """Components, dependency edges and component findings for one snapshot (computed once per call)."""

    def __init__(self, snap: Snapshot) -> None:
        self.snap = snap
        self.components: list[Component] = components.detect(snap)
        self.edges: list[Edge] = dependencies.build(snap, self.components)
        self.findings: dict[str, list[Finding]] = {}
        for c in self.components:
            clients = {e.client.namespace for e in dependencies.clients_of(self.edges, c.key)}
            self.findings[c.key] = components.diagnose_component(snap, c, clients, self.components)
        for c in self.components:  # cross-layer: log pipelines feeding an unhealthy store
            if c.layer == "logging":
                self.findings[c.key] += dependencies.pipeline_findings(c, self.edges, self.findings)
        # Not tied to one component: routing, TLS, GitOps, secrets, autoscaling, storage, policy, backups,
        # monitoring/alerts, nodes, load balancers, mesh, and usage (metrics-server)
        self.secret_findings = ops.secret_findings(snap)
        self.platform: list[Finding] = (
            layers.ingress_findings(snap, self.components)
            + layers.certificate_findings(snap)
            + ops.all_findings(snap)
            + usage.usage_findings(snap)
        )

    def component(self, key: str) -> Component | None:
        return next((c for c in self.components if c.key == key), None)

    def find(self, namespace: str, name: str) -> Component | None:
        """By component name, or by a controller/pod that belongs to it."""
        for c in self.components:
            if c.namespace == namespace and c.name == name:
                return c
        for c in self.components:
            if c.namespace != namespace:
                continue
            if any(s.name == name for s in c.specs) or any(p.name == name or p.workload.name == name for p in c.pods):
                return c
        return None

    def owning(self, wl: WorkloadRef) -> Component | None:
        for c in self.components:
            if any(s.ref == wl for s in c.specs) or any(p.workload == wl for p in c.pods):
                return c
        return None


class Kubemedic:
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

    def _log_signals(self, snap: Snapshot, wl: WorkloadRef) -> dict[str, list[LogSignal]]:
        """Signatures from the logs of this workload's failing containers, per container name
        (opt-in via KUBEMEDIC_READ_LOGS; at most 2 containers read)."""
        if not self.settings.read_logs:
            return {}
        found: dict[str, list[LogSignal]] = {}
        budget = 2
        for p in snap.pods_of(wl):
            for c in p.app_containers:
                failing = not c.ready or c.restart_count > 0 or c.last_state.reason in ("Error", "OOMKilled")
                if budget == 0 or c.name in found or not failing or p.phase in ("Pending", "Succeeded"):
                    continue
                budget -= 1
                text = read_logs(self.source, p.namespace, p.name, c.name, previous=c.restart_count > 0)
                if text is None and c.restart_count > 0:
                    text = read_logs(self.source, p.namespace, p.name, c.name, previous=False)
                sigs = logsig.analyze(text or "")
                if sigs:
                    found[c.name] = sigs
        return found

    def _diagnose(
        self, snap: Snapshot, wl: WorkloadRef, analysis: Analysis, include_hygiene: bool
    ) -> tuple[list[Finding], list[LogSignal], list[Edge]]:
        """Workload findings with dependency root causes first."""
        per_container = self._log_signals(snap, wl)
        signals = [x for sigs in per_container.values() for x in sigs]
        own = diagnose.diagnose_workload(snap, wl, include_hygiene=include_hygiene, log_signals=per_container)
        comp = analysis.owning(wl)
        if comp is not None:  # a pod of Kafka/OpenSearch/...: the component view explains it better
            extra = [f for f in analysis.findings.get(comp.key, []) if f.id not in {x.id for x in own}]
            own = own + extra
        deps = dependencies.dependencies_of(analysis.edges, wl)
        upstream = dependencies.upstream_findings(wl, snap.pods_of(wl), own, analysis.edges, analysis.findings, signals)
        routing = [f for f in analysis.platform if any(h.params.get("workload") == wl.key for h in f.remediations)]
        seen = {f.id for f in own}
        about_wl = [f for f in analysis.platform if f.workload == wl and f.id not in seen]  # HPA, alerts, policy, usage
        upstream = ops.secret_root_causes(analysis.snap, wl, own, analysis.secret_findings) + upstream
        own = (
            own
            + about_wl
            + [
                f.model_copy(
                    update={
                        "title": f"Users affected: {f.title}",
                        "remediations": [],
                    }
                )
                for f in routing
            ]
        )
        ordered = sorted(upstream, key=lambda f: -f.severity) + sorted(own, key=lambda f: -f.severity)
        return ordered, signals, deps

    def _analysis(self, snap: Snapshot, namespace: str | None) -> Analysis:
        """Dependencies cross namespaces (shop -> data), so component analysis always uses the whole cluster."""
        return Analysis(snap if not namespace else self._snap(None))

    def _meta(self, snap: Snapshot) -> dict[str, Any]:
        return {"source": self.source.name, "as_of": snap.now.isoformat(), "warnings": snap.warnings}

    # ------------------------------------------------------------ read tools

    def _platform_filter(
        self, incidents: list[SecurityIncident], namespace: str | None, include_system: bool
    ) -> tuple[list[SecurityIncident], int]:
        """Platform components (Falco, Trivy, kube-system) are privileged by design; hide them from
        cluster-wide security views unless asked, so real application risk isn't drowned out."""
        if namespace or include_system:
            return incidents, 0
        sysns = self.settings.system_namespaces
        kept = [i for i in incidents if i.workload.namespace not in sysns]
        return kept, len(incidents) - len(kept)

    def cluster_health(self, namespace: str | None = None, include_system: bool = False) -> dict[str, Any]:
        snap = self._snap(namespace)
        findings = diagnose.diagnose_all(snap, min_severity=Severity.MEDIUM)
        incidents, hidden = self._platform_filter(
            [i for i in security.triage(snap, self.allowlist) if i.score >= 45], namespace, include_system
        )
        unhealthy_nodes = [n.name for n in snap.nodes if not n.ready]
        analysis = self._analysis(snap, namespace)
        comp_rows = []
        for c in analysis.components:
            if namespace and c.namespace != k8s_name(namespace):
                continue
            fs = analysis.findings[c.key]
            top = max(fs, key=lambda f: f.severity, default=None)
            comp_rows.append(
                {
                    "component": c.label,
                    "layer": c.layer,
                    "status": components.status_of(fs),
                    "issues": len([f for f in fs if f.severity >= Severity.MEDIUM]),
                    "top_issue": clean(top.title, 160) if top and top.severity >= Severity.MEDIUM else None,
                }
            )
        root_cause: dict[str, str] = {}
        for wl in {f.workload for f in findings}:
            up = dependencies.upstream_findings(
                wl, snap.pods_of(wl), [f for f in findings if f.workload == wl], analysis.edges, analysis.findings
            )
            first = max(up, key=lambda f: f.severity, default=None)
            if first is not None and first.title.startswith("Likely root cause: "):
                root_cause[wl.key] = first.title.removeprefix("Likely root cause: ")
        order = {"down": 0, "critical": 1, "degraded": 2, "at-risk": 3, "healthy": 4}
        comp_rows.sort(key=lambda r: (order.get(str(r["status"]), 9), -int(str(r["issues"]))))
        return {
            **self._meta(snap),
            "workloads": len(snap.workloads()),
            "pods": len(snap.pods),
            "nodes": {"total": len(snap.nodes), "not_ready": unhealthy_nodes},
            "reliability_issues": [
                {
                    "workload": f.workload.key,
                    "severity": f.severity.label,
                    "title": clean(f.title, 160),
                    **(
                        {"likely_root_cause": clean(root_cause[f.workload.key], 160)}
                        if f.workload.key in root_cause
                        else {}
                    ),
                }
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
            "components": comp_rows[:MAX_ITEMS],
            "platform_issues": [
                {
                    "area": _area(f),
                    "object": f.workload.key,
                    "severity": f.severity.label,
                    "title": clean(f.title, 160),
                }
                for f in sorted(analysis.platform, key=lambda f: -f.severity)
                if (not namespace or f.workload.namespace == k8s_name(namespace)) and f.severity >= Severity.MEDIUM
            ][: MAX_ITEMS * 2],
            **({"capacity": cap} if (cap := usage.capacity_summary(analysis.snap)) else {}),
            "platform_incidents_hidden": hidden,
            "next_steps": "Use diagnose_workload, diagnose_component or investigate_security for details on any item."
            + (" Pass include_system=true to also see platform namespaces." if hidden else ""),
        }

    def diagnose_workload(self, namespace: str, name: str, include_hygiene: bool = True) -> dict[str, Any]:
        snap = self._snap(namespace)
        wl = self._workload(snap, namespace, name)
        analysis = self._analysis(snap, namespace)
        findings, signals, deps = self._diagnose(snap, wl, analysis, include_hygiene)
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
            "depends_on": [
                {
                    "component": e.component_label,
                    "service": e.service,
                    "via_env": e.env_var,
                    "status": components.status_of(analysis.findings.get(e.component, [])),
                }
                for e in deps
            ],
            "log_signals": [_signal(x) for x in signals],
            "findings": [finding_dict(f) for f in findings],
        }

    def find_problems(self, namespace: str | None = None, min_severity: str = "medium") -> dict[str, Any]:
        snap = self._snap(namespace)
        sev = Severity[min_severity.upper()]
        findings = diagnose.diagnose_all(snap, include_hygiene=sev <= Severity.LOW, min_severity=sev)
        analysis = self._analysis(snap, namespace)
        seen = {f.id for f in findings}
        for fs in [*analysis.findings.values(), analysis.platform]:
            findings += [f for f in fs if f.severity >= sev and f.id not in seen]
        if namespace:
            findings = [f for f in findings if f.workload.namespace == k8s_name(namespace)]
        for wl in {f.workload for f in findings if f.workload.kind not in ("Component", "Ingress", "Certificate")}:
            own = [f for f in findings if f.workload == wl]
            findings += dependencies.upstream_findings(wl, snap.pods_of(wl), own, analysis.edges, analysis.findings)
        findings.sort(key=lambda f: (-f.severity, f.workload.key))
        return {
            **self._meta(snap),
            "count": len(findings),
            "findings": [finding_dict(f) for f in findings[:MAX_ITEMS]],
        }

    def security_triage(
        self,
        namespace: str | None = None,
        since_hours: int | None = None,
        min_score: int = 10,
        include_system: bool = False,
    ) -> dict[str, Any]:
        snap = self._snap(namespace)
        since = timedelta(hours=since_hours) if since_hours else None
        incidents, hidden = self._platform_filter(
            security.triage(snap, self.allowlist, since=since, min_score=min_score), namespace, include_system
        )
        return {
            **self._meta(snap),
            "scoring": "Explicit points per signal (see docs/scoring.md); x1.5 when runtime alerts "
            "co-occur with exploitable CVEs or excessive exposure. 70+ critical, 45+ high, 25+ medium.",
            "incidents": [incident_dict(i) for i in incidents[:MAX_ITEMS]],
            "suppressed_by_allowlist": sum(i.suppressed_alerts for i in incidents),
            "platform_incidents_hidden": hidden,
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
            raise RuntimeError("GitOps change flow disabled: set KUBEMEDIC_GITOPS_REPO to a local clone")
        return self.plans

    def _target(
        self, snap: Snapshot, analysis: Analysis, namespace: str, name: str
    ) -> tuple[WorkloadRef, Component | None]:
        """A workload, or a component (Kafka/Redis/...) by name. Components target their CR or controller."""
        ns, nm = k8s_name(namespace), k8s_name(name)
        wl = snap.find_workload(ns, nm)
        comp = analysis.owning(wl) if wl else analysis.find(ns, nm)
        if wl is None and comp is None:
            raise NotFound(f"no workload, pod or component named {name!r} in namespace {namespace!r}")
        if comp is not None and (wl is None or comp.name == nm):
            return comp.ref, comp
        assert wl is not None
        return wl, comp

    def plan_remediation(self, namespace: str, name: str, kinds: list[str] | None = None) -> dict[str, Any]:
        store = self._require_plans()
        snap = self._snap(namespace)
        analysis = self._analysis(snap, namespace)
        wl, comp = self._target(snap, analysis, namespace, name)
        findings: list[Finding] = []
        if snap.pods_of(wl):
            findings = diagnose.diagnose_workload(snap, wl, log_signals=self._log_signals(snap, wl))
        if comp is not None:
            findings += analysis.findings.get(comp.key, [])
        inc = next((i for i in security.triage(snap, self.allowlist) if i.workload == wl), None)
        reliability: dict[str, RemediationHint] = {}
        sec: dict[str, RemediationHint] = {}
        source_of: dict[str, list[Finding]] = {}
        comp_ids = {f.id for f in analysis.findings.get(comp.key, [])} if comp else set()
        # Component checks know the system (JVM heap, Kafka config): their hints win over generic ones.
        for f in sorted(findings, key=lambda f: (-f.severity, f.id not in comp_ids)):
            for h in f.remediations:
                key = _hint_key(h)
                (sec if f.category == "security" else reliability).setdefault(key, h)
                source_of.setdefault(key, []).append(f)
        for h in inc.remediations if inc else []:
            sec.setdefault(_hint_key(h), h)  # component-specific hints (scoped selectors, client namespaces) win
        hints = {**sec, **reliability}
        if kinds:
            # a kind selects every hint of that kind ("set-fluentbit-option"), or one exact key
            selected = [h for k, h in hints.items() if k in kinds or h.kind in kinds]
            unknown = {k for k in kinds if not any(k in (key, h.kind) for key, h in hints.items())}
            if unknown:
                avail = sorted({h.kind for h in hints.values()} | set(hints))
                raise ValueError(f"not applicable to {wl.key}: {sorted(unknown)}; available: {avail or 'none'}")
        else:
            # One concern per PR: reliability fixes first; otherwise security hardening.
            # Opt-in only: rollback-template (supersedes field edits) and isolate-workload (cuts traffic).
            auto = {k: h for k, h in reliability.items() if h.kind in remediation.AUTOMATABLE}
            pool = auto or reliability or sec
            selected = [h for h in pool.values() if h.kind not in ("rollback-template", "isolate-workload")]
        addressed = {f.id: f for h in selected for f in source_of.get(_hint_key(h), [])}
        evidence = "; ".join(clean(f.explanation, 300) for f in list(addressed.values())[:2])
        if inc and any(_hint_key(h) in sec for h in selected):
            evidence = (evidence + " | " if evidence else "") + clean(inc.summary, 300)
        result = remediation.build(store.repo, snap, wl, selected)
        plan, token = store.create(
            wl,
            result,
            evidence or "operator request",
            addresses=[{"id": f.id, "title": clean(f.title, 200)} for f in addressed.values()],
            baseline=sorted({f.id for f in findings}),
        )
        return self._plan_out(store, plan, token, sorted({h.kind for h in hints.values()}))

    def _plan_out(self, store: PlanStore, plan: ChangePlan, token: str, available: list[str]) -> dict[str, Any]:
        out = plan.public()
        out["approval_token"] = token
        out["available_kinds"] = available
        out["instructions"] = (
            "Show the diff, notes and policy results to the human and get explicit approval before calling "
            "commit_plan. Nothing touches the cluster: commit_plan creates a Git branch for review."
            + (
                " Approval mode is 'cli': the human must also run `kubemedic approve <id>`."
                if store.approval_mode == "cli"
                else ""
            )
        )
        return out

    def verify_fix(self, plan_id: str) -> dict[str, Any]:
        """After a plan's PR is merged and synced: are the findings it targeted actually gone?"""
        store = self._require_plans()
        plan = store.get(plan_id)
        merged = merge_state(store.repo, plan)
        snap = self._snap(plan.workload.namespace)
        analysis = self._analysis(snap, plan.workload.namespace)
        current: list[Finding] = []
        wl = plan.workload
        if snap.pods_of(wl):
            current = self._diagnose(snap, wl, analysis, include_hygiene=True)[0]
        comp = analysis.owning(wl) or next((c for c in analysis.components if c.ref == wl), None)
        if comp is not None:
            current += analysis.findings.get(comp.key, [])
        ids = {f.id for f in current}
        still = [a for a in plan.addresses if a["id"] in ids]
        gone = [a for a in plan.addresses if a["id"] not in ids]
        apps = [
            {
                "application": cr.name,
                "sync": clean(str((cr.status.get("sync") or {}).get("status") or "unknown"), 30),
                "health": clean(str((cr.status.get("health") or {}).get("status") or "unknown"), 30),
            }
            for cr in snap.custom_resources
            if cr.kind == "Application" and ((cr.spec.get("destination") or {}).get("namespace")) == wl.namespace
        ]
        if merged["state"] != "merged":
            verdict = "not-merged"
        elif not plan.addresses:
            verdict = "merged (no tracked findings to compare)"
        elif not still:
            verdict = "fixed"
        elif any(a["sync"] == "OutOfSync" for a in apps):
            verdict = "merged-awaiting-sync"
        else:
            verdict = "merged-but-not-fixed"
        hint = {
            "fixed": "The targeted findings are gone from the live cluster.",
            "not-merged": "Merge the PR, let your GitOps controller sync, then verify again.",
            "merged-awaiting-sync": "Your GitOps controller has not applied the change yet; check again shortly.",
            "merged-but-not-fixed": "The change is live but the problem remains: diagnose again; plan_revert "
            "undoes this change if it made things worse.",
        }.get(verdict, "")
        return {
            **self._meta(snap),
            "plan_id": plan.id,
            "workload": wl.key,
            "verdict": verdict,
            "merge": merged,
            "resolved": gone,
            "still_present": still,
            # Only issues that did not exist when the plan was made; pre-existing ones are listed separately.
            "new_findings": [
                {"severity": f.severity.label, "title": clean(f.title, 200)}
                for f in _unique(current)
                if f.severity >= Severity.HIGH
                and f.id not in {a["id"] for a in plan.addresses}
                and (plan.baseline is None or f.id not in set(plan.baseline))
            ][:10],
            "still_open_not_targeted": [
                {"severity": f.severity.label, "title": clean(f.title, 200)}
                for f in _unique(current)
                if f.severity >= Severity.HIGH
                and plan.baseline is not None
                and f.id in set(plan.baseline)
                and f.id not in {a["id"] for a in plan.addresses}
            ][:10],
            "gitops_applications": apps[:10],
            "next": hint,
        }

    def plan_revert(self, plan_id: str) -> dict[str, Any]:
        """A new plan that undoes a committed plan (same diff/policy/approval flow, nothing is auto-applied)."""
        store = self._require_plans()
        original = store.get(plan_id)
        if original.status != "committed" or not original.commit:
            raise ValueError(
                f"plan {plan_id} is {original.status}; only committed plans can be reverted "
                "(an unmerged branch can simply be closed)"
            )
        state = merge_state(store.repo, original)
        changes = revert_changes(store.repo, original)
        if not changes:
            raise ValueError(f"nothing to revert: HEAD does not contain plan {plan_id}'s changes ({state['detail']})")
        result = RemediationResult(
            changes=changes,
            applied=[f"revert: {a}" for a in original.applied] or [f"revert plan {plan_id}"],
            manual=[],
            notes=["Reverting restores the previous manifests, including any problem they had."]
            + ([] if state["state"] == "merged" else [f"Plan {plan_id} may not be merged: {state['detail']}"]),
        )
        plan, token = store.create(
            original.workload,
            result,
            f"Revert of plan {plan_id}: {original.evidence_summary}"[:600],
            reverts=plan_id,
        )
        return self._plan_out(store, plan, token, [])

    # ------------------------------------------------------------ components

    def list_components(self, namespace: str | None = None) -> dict[str, Any]:
        snap = self._snap(namespace)
        analysis = self._analysis(snap, namespace)
        rows = []
        for c in analysis.components:
            if namespace and c.namespace != k8s_name(namespace):
                continue
            fs = analysis.findings[c.key]
            rows.append(
                {
                    "component": c.label,
                    "kind": c.kind,
                    "layer": c.layer,
                    "namespace": c.namespace,
                    "name": c.name,
                    "managed_by": clean(c.managed_by, 80),
                    "version": clean(c.version, 60) or None,
                    "members": f"{c.ready}/{c.desired} ready",
                    "status": components.status_of(fs),
                    "issues": {s.label: n for s in Severity if (n := sum(f.severity == s for f in fs))},
                    "clients": sorted({e.client.key for e in dependencies.clients_of(analysis.edges, c.key)})[:10],
                }
            )
        return {
            **self._meta(snap),
            "count": len(rows),
            "components": rows[:50],
            "next_steps": "diagnose_component(namespace, name) for checks, evidence and fixes.",
        }

    def diagnose_component(self, namespace: str, name: str) -> dict[str, Any]:
        snap = self._snap(namespace)
        analysis = self._analysis(snap, namespace)
        comp = analysis.find(k8s_name(namespace), k8s_name(name))
        if comp is None:
            raise NotFound(
                f"no component (data store, ingress controller, gateway or log agent) named {name!r} "
                f"in namespace {namespace!r}"
            )
        fs = analysis.findings[comp.key]
        clients = dependencies.clients_of(analysis.edges, comp.key)
        return {
            **self._meta(snap),
            "component": comp.label,
            "kind": comp.kind,
            "layer": comp.layer,
            "managed_by": clean(comp.managed_by, 80),
            "version": clean(comp.version, 60) or None,
            "remediation_target": comp.ref.key,
            "status": components.status_of(fs),
            "members": [
                {"pod": p.name, "node": p.node, "phase": p.phase, "ready": all(c.ready for c in p.app_containers)}
                for p in comp.pods[:20]
            ],
            "services": [
                {"name": s.name, "type": s.type, "ports": [x.port for x in s.ports]} for s in comp.services[:10]
            ],
            "clients": [{"workload": e.client.key, "service": e.service, "via_env": e.env_var} for e in clients[:20]],
            **(
                {
                    "routes": [
                        {"ingress": f"{i.namespace}/{i.name}", "hosts": i.hosts[:5]}
                        for i, _ in layers.routes_of(analysis.snap, comp, analysis.components)
                    ][:20]
                }
                if comp.layer == "edge"
                else {}
            ),
            **(
                {
                    "ships_to": [
                        {"component": e.component_label, "service": e.service, "output": e.env_var.split(":", 1)[1]}
                        for e in analysis.edges
                        if e.client == comp.ref and e.env_var.startswith("output:")
                    ]
                }
                if comp.layer == "logging"
                else {}
            ),
            "findings": [finding_dict(f) for f in fs],
        }

    def commit_plan(self, plan_id: str, approval_token: str) -> dict[str, Any]:
        store = self._require_plans()
        plan: ChangePlan = store.commit(plan_id, approval_token)
        return {
            "plan_id": plan.id,
            "status": "dry-run (nothing written; set KUBEMEDIC_DRY_RUN=false to commit)"
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
                    **(
                        {"merge": merge_state(store.repo, p)["state"], "reverts": p.reverts}
                        if p.status == "committed"
                        else {}
                    ),
                }
                for p in store.all_plans()[:MAX_ITEMS]
            ],
            "note": "Only plans in this kubemedic state directory exist; branch names remembered from an earlier "
            "conversation or a reset lab may be gone. merge: merged | not-merged (local refs).",
        }

    def change_history(self, limit: int = 20) -> dict[str, Any]:
        return {"events": self._require_plans().history(max(1, min(limit, 200)))}


def build_from_settings(settings: Settings) -> Kubemedic:
    source: ClusterSource
    if settings.source == "fixture":
        from kubemedic import demo
        from kubemedic.source.fixture import FixtureSource

        source = FixtureSource(settings.fixture_dir or demo.CLUSTER)
        if settings.fixture_dir is None and settings.allowlist is None:
            from dataclasses import replace

            settings = replace(settings, allowlist=demo.ALLOWLIST)
    else:
        from kubemedic.source.alerts import AlertStore
        from kubemedic.source.kube import KubeSource

        alerts = AlertStore(settings.alerts_db) if settings.alerts_db else None
        source = KubeSource(context=settings.kube_context, alerts=alerts, falco_window=settings.falco_window)
    return Kubemedic(source, settings)
