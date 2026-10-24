"""Platform layers around the apps: edge (ingress-nginx + ModSecurity, Kong), log pipeline (Fluent Bit,
Fluentd, Vector), routing (Ingress → Service → pods) and certificates (cert-manager).

Facts used here were checked against upstream docs/source (docs/platform-notes.md): ingress-nginx retirement
(no releases after March 2026), IngressNightmare fixed versions, ModSecurity defaults (DetectionOnly), Kong
admin ports, Fluent Bit ``Retry_Limit`` default (1) and ``Mem_Buf_Limit`` (unbounded by default).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from kubepilot.engine import fluentbit, selectors
from kubepilot.models import Evidence, Finding, IngressInfo, Pod, RemediationHint, ServiceInfo, Severity, WorkloadRef
from kubepilot.normalize import ts
from kubepilot.sanitize import clean
from kubepilot.source.base import Snapshot

if TYPE_CHECKING:
    from kubepilot.engine.components import Component

# kind -> (layer, display name). Detected from container images (see classify_platform_image).
CATALOG: dict[str, tuple[str, str]] = {
    # edge / gateways
    "ingress-nginx": ("edge", "ingress-nginx"),
    "kong": ("edge", "Kong"),
    "traefik": ("edge", "Traefik"),
    "envoy-gateway": ("edge", "Envoy Gateway"),
    # log & telemetry pipeline
    "fluent-bit": ("logging", "Fluent Bit"),
    "fluentd": ("logging", "Fluentd"),
    "vector": ("logging", "Vector"),
    "promtail": ("logging", "Promtail"),
    "alloy": ("logging", "Grafana Alloy"),
    "otel-collector": ("logging", "OpenTelemetry Collector"),
    "loki": ("logging", "Loki"),
    # monitoring
    "prometheus": ("monitoring", "Prometheus"),
    "alertmanager": ("monitoring", "Alertmanager"),
    "metrics-server": ("monitoring", "metrics-server"),
    # cluster services
    "coredns": ("network", "CoreDNS"),
    "cilium": ("network", "Cilium"),
    "calico": ("network", "Calico"),
    "istio": ("mesh", "Istio (istiod)"),
    "linkerd": ("mesh", "Linkerd"),
    "argocd": ("gitops", "Argo CD"),
    "flux": ("gitops", "Flux"),
    "external-secrets": ("secrets", "External Secrets Operator"),
    "sealed-secrets": ("secrets", "Sealed Secrets"),
    "cert-manager": ("tls", "cert-manager"),
    "kyverno": ("policy", "Kyverno"),
    "gatekeeper": ("policy", "OPA Gatekeeper"),
    "keda": ("autoscaling", "KEDA"),
    "karpenter": ("autoscaling", "Karpenter"),
    "cluster-autoscaler": ("autoscaling", "Cluster Autoscaler"),
    "longhorn": ("storage", "Longhorn"),
    "rook-ceph": ("storage", "Rook Ceph"),
    "velero": ("backup", "Velero"),
    "aws-lb-controller": ("cloud", "AWS Load Balancer Controller"),
}
EDGE_KINDS = {k for k, (layer, _) in CATALOG.items() if layer == "edge"}
LOGGING_KINDS = {k for k, (layer, _) in CATALOG.items() if layer == "logging"}
DAEMON_KINDS = LOGGING_KINDS | {"cilium", "calico"}  # usually DaemonSets
PLATFORM_DISPLAY = {k: d for k, (_, d) in CATALOG.items()}
KONG_ADMIN_PORTS = {8001, 8444, 8002, 8445}  # Admin API (http/https) and Kong Manager (http/https)
INGRESS_NGINX_RETIRED = datetime(2026, 4, 1, tzinfo=UTC)  # "best-effort maintenance until March 2026"
PROMTAIL_EOL = datetime(2026, 3, 2, tzinfo=UTC)  # Grafana: "Promtail is end of life (EOL) as of March 2, 2026"


def layer_of(kind: str) -> str:
    return CATALOG.get(kind, ("data", ""))[0]


# (substring of the image path, kind); first match wins. Paths are lower-cased, tag and digest removed.
_IMAGE_RULES: list[tuple[str, str]] = [
    ("ingress-nginx/controller", "ingress-nginx"),
    ("kubernetes-ingress-controller", ""),  # Kong's controller, not the gateway
    ("envoyproxy/gateway", "envoy-gateway"),
    ("grafana/promtail", "promtail"),
    ("grafana/alloy", "alloy"),
    ("grafana/loki", "loki"),
    ("opentelemetry-collector", "otel-collector"),
    ("prometheus/prometheus", "prometheus"),
    ("prom/prometheus", "prometheus"),
    ("prometheus/alertmanager", "alertmanager"),
    ("prom/alertmanager", "alertmanager"),
    ("metrics-server/metrics-server", "metrics-server"),
    ("coredns/coredns", "coredns"),
    ("cilium/cilium", "cilium"),
    ("calico/node", "calico"),
    ("istio/pilot", "istio"),
    ("linkerd/controller", "linkerd"),
    ("linkerd/destination", "linkerd"),
    ("argoproj/argocd", "argocd"),
    ("fluxcd/source-controller", "flux"),
    ("fluxcd/kustomize-controller", "flux"),
    ("fluxcd/helm-controller", "flux"),
    ("external-secrets/external-secrets", "external-secrets"),
    ("sealed-secrets-controller", "sealed-secrets"),
    ("jetstack/cert-manager-controller", "cert-manager"),
    ("kyverno/kyverno", "kyverno"),
    ("openpolicyagent/gatekeeper", "gatekeeper"),
    ("kedacore/keda", "keda"),
    ("karpenter/controller", "karpenter"),
    ("cluster-autoscaler", "cluster-autoscaler"),
    ("longhornio/longhorn-manager", "longhorn"),
    ("rook/ceph", "rook-ceph"),
    ("velero/velero", "velero"),
    ("aws-load-balancer-controller", "aws-lb-controller"),
]


def classify_platform_image(image: str) -> str | None:
    repo = image.split("@")[0].lower()
    path = repo.rsplit(":", 1)[0] if ":" in repo.rsplit("/", 1)[-1] else repo
    last = path.rsplit("/", 1)[-1]
    for needle, kind in _IMAGE_RULES:
        if needle in path:
            return kind or None
    # Distribution mirrors flatten "org/name" into one segment: k3s ships rancher/mirrored-coredns-coredns,
    # rancher/mirrored-metrics-server, rancher/mirrored-library-traefik (seen on a real k3s lab).
    if last.startswith("mirrored-"):
        flat = last.removeprefix("mirrored-library-").removeprefix("mirrored-")
        for needle, kind in _IMAGE_RULES:
            org_name = needle.replace("/", "-")
            if kind and (flat == org_name or flat == needle.rsplit("/", 1)[-1] or flat.startswith(org_name)):
                return kind
    if last in ("kong", "kong-gateway", "kong-enterprise-edition"):
        return "kong"
    if last == "traefik" or last.endswith("-traefik"):  # k3s ships rancher/mirrored-library-traefik
        return "traefik"
    if last in ("fluent-bit", "fluentbit"):
        return "fluent-bit"
    if last.startswith("fluentd"):
        return "fluentd"
    if last == "vector" and ("timberio" in path or "vectordotdev" in path):
        return "vector"
    return None


# What it means for users when a cluster service is down: (severity, impact sentence).
IMPACT: dict[str, tuple[Severity, str]] = {
    "coredns": (Severity.CRITICAL, "DNS resolution fails for every pod: services cannot find each other."),
    "cilium": (Severity.CRITICAL, "Pods on affected nodes lose networking and policy enforcement."),
    "calico": (Severity.CRITICAL, "Pods on affected nodes lose networking and policy enforcement."),
    "istio": (Severity.HIGH, "New pods get no mesh config or certificates; workload certificates stop rotating."),
    "linkerd": (Severity.HIGH, "Meshed pods cannot get identities or service discovery updates."),
    "argocd": (
        Severity.HIGH,
        "Changes merged to Git are no longer applied to the cluster (including kubepilot fixes).",
    ),
    "flux": (Severity.HIGH, "Changes merged to Git are no longer applied to the cluster (including kubepilot fixes)."),
    "external-secrets": (Severity.HIGH, "Secrets stop syncing from the secret store; rotations and new secrets fail."),
    "sealed-secrets": (Severity.HIGH, "New or updated SealedSecrets are not decrypted into Secrets."),
    "cert-manager": (Severity.HIGH, "Certificates are not issued or renewed and will expire."),
    "kyverno": (
        Severity.HIGH,
        "Its admission webhooks may reject every create/update (failurePolicy Fail) or stop enforcing policy.",
    ),
    "gatekeeper": (Severity.HIGH, "Its admission webhook may reject every create/update or stop enforcing policy."),
    "metrics-server": (Severity.HIGH, "HPAs cannot read CPU/memory and stop scaling; `kubectl top` fails."),
    "keda": (Severity.HIGH, "Event-driven autoscaling stops: workloads stay at their current replica count."),
    "karpenter": (Severity.HIGH, "No new nodes are provisioned: pods that need capacity stay Pending."),
    "cluster-autoscaler": (Severity.HIGH, "No new nodes are added: pods that need capacity stay Pending."),
    "longhorn": (Severity.CRITICAL, "Volumes cannot be attached or repaired: stateful pods cannot start."),
    "rook-ceph": (Severity.CRITICAL, "Ceph-backed volumes may become unavailable."),
    "velero": (Severity.MEDIUM, "Scheduled backups are not running."),
    "prometheus": (Severity.HIGH, "Monitoring is blind: no metrics and no alerts fire."),
    "alertmanager": (Severity.HIGH, "Alerts fire but nobody is notified."),
    "loki": (Severity.HIGH, "Logs cannot be stored or queried."),
    "aws-lb-controller": (Severity.HIGH, "LoadBalancer Services and Ingresses on AWS get no load balancer."),
    "traefik": (Severity.CRITICAL, "Every route served by Traefik is unreachable from outside."),
    "envoy-gateway": (Severity.CRITICAL, "Gateways managed by Envoy Gateway stop serving traffic."),
}


def _fid(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:10]


def _version(image: str) -> tuple[int, int, int] | None:
    tag = image.split("@")[0].rsplit(":", 1)[-1] if ":" in image.split("@")[0].rsplit("/", 1)[-1] else ""
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


# ---------------------------------------------------------------- routing (Ingress -> Service -> pods)


def service_pods(snap: Snapshot, svc: ServiceInfo) -> list[Pod]:
    if not svc.selector:
        return []
    return [
        p
        for p in snap.pods
        if p.namespace == svc.namespace and all(p.labels.get(k) == v for k, v in svc.selector.items())
    ]


def _ready(p: Pod) -> bool:
    app = p.app_containers
    return p.phase == "Running" and bool(app) and all(c.ready for c in app)


def controller_for(ing: IngressInfo, snap: Snapshot, comps: list[Component]) -> Component | None:
    """The edge component serving an Ingress, via IngressClass.controller or the class name."""
    edge = [c for c in comps if c.kind in EDGE_KINDS]
    cls = ing.ingress_class
    if cls is None:
        default = next((c for c in snap.ingress_classes if c.default), None)
        cls = default.name if default else None
    ic = next((c for c in snap.ingress_classes if c.name == cls), None)
    hint = (ic.controller if ic else "") + " " + (cls or "")
    if "konghq" in hint or "kong" in hint:
        return next((c for c in edge if c.kind == "kong"), None)
    if "ingress-nginx" in hint or "nginx" in hint:
        return next((c for c in edge if c.kind == "ingress-nginx"), None)
    return edge[0] if len(edge) == 1 and cls is None else None


def ingress_findings(snap: Snapshot, comps: list[Component]) -> list[Finding]:
    """Ingress rules pointing at Services that don't exist or have no ready pods (users get 503/404)."""
    out: list[Finding] = []
    for ing in snap.ingresses:
        ref = WorkloadRef(kind="Ingress", namespace=ing.namespace, name=ing.name)
        for path in ing.paths:
            if not path.service:
                continue
            where = f"{path.host or '*'}{path.path}"
            svc = next((s for s in snap.services if s.namespace == ing.namespace and s.name == path.service), None)
            if svc is None:
                out.append(
                    Finding(
                        id=_fid(ref.key, "missing", path.service),
                        workload=ref,
                        category="reliability",
                        title=f"Ingress {ing.namespace}/{ing.name} routes {where} to missing Service {path.service}",
                        severity=Severity.HIGH,
                        explanation="Requests for this path fail (404/503 from the ingress controller) because the "
                        "backend Service does not exist. A rename or a deleted Service is the usual cause.",
                        evidence=[Evidence(source="ingress", detail=f"{where} -> service {path.service}")],
                    )
                )
                continue
            pods = service_pods(snap, svc)
            if svc.selector and not any(_ready(p) for p in pods):
                owners = sorted({p.workload.key for p in pods})
                out.append(
                    Finding(
                        id=_fid(ref.key, "noready", path.service),
                        workload=ref,
                        category="reliability",
                        title=f"Ingress {ing.namespace}/{ing.name}: {where} has no ready backend ({path.service})",
                        severity=Severity.HIGH,
                        explanation="Users requesting this path get 503 errors: Service "
                        f"{path.service} selects {len(pods)} pod(s) and none is ready."
                        + (
                            f" Diagnose {', '.join(owners)} for the cause."
                            if owners
                            else " No pod matches its selector."
                        ),
                        evidence=[Evidence(source="ingress", detail=f"{where} -> {path.service}: 0/{len(pods)} ready")],
                        remediations=[
                            RemediationHint(
                                kind="investigate-workload",
                                params={"workload": owners[0]} if owners else {},
                                summary=f"Run diagnose_workload on {owners[0]}"
                                if owners
                                else "Fix the Service selector",
                            )
                        ],
                    )
                )
    return out


def routes_of(snap: Snapshot, comp: Component, comps: list[Component]) -> list[tuple[IngressInfo, list[str]]]:
    return [(i, i.hosts) for i in snap.ingresses if controller_for(i, snap, comps) is comp]


# ---------------------------------------------------------------- certificates (cert-manager)


def certificate_findings(snap: Snapshot, now: datetime | None = None) -> list[Finding]:
    now = now or snap.now
    out: list[Finding] = []
    for cr in snap.custom_resources:
        if cr.kind != "Certificate" or cr.group != "cert-manager.io":
            continue
        ref = WorkloadRef(kind="Certificate", namespace=cr.namespace, name=cr.name)
        names = ", ".join(str(n) for n in (cr.spec.get("dnsNames") or [])[:4]) or cr.name
        not_after = ts(cr.status.get("notAfter"))
        ready = next((c for c in cr.conditions if c.type == "Ready"), None)
        ev = [Evidence(source="cert-manager", detail=f"dnsNames: {clean(names, 200)}")]
        if not_after:
            ev.append(Evidence(source="cert-manager", detail=f"notAfter: {not_after.isoformat()}"))
        if ready is not None and ready.status == "False":
            ev.append(
                Evidence(source="cert-manager", detail=f"Ready=False {ready.reason or ''}: {clean(ready.message, 240)}")
            )
        issuing = next((c for c in cr.conditions if c.type == "Issuing" and c.reason == "Failed"), None)
        if issuing is not None:
            ev.append(Evidence(source="cert-manager", detail=f"renewal failing: {clean(issuing.message, 240)}"))
        if not_after and not_after <= now:
            sev, title, expl = (
                Severity.CRITICAL,
                f"Certificate {cr.namespace}/{cr.name} has expired",
                f"Clients connecting to {names} get TLS errors. cert-manager could not renew it; its status says why.",
            )
        elif not_after and not_after - now <= timedelta(days=7):
            days = max(0, (not_after - now).days)
            sev, title, expl = (
                Severity.HIGH,
                f"Certificate {cr.namespace}/{cr.name} expires in {days} day(s)",
                "cert-manager normally renews well before expiry (default: at 2/3 of the lifetime); a certificate "
                "this close to expiry means renewal is failing.",
            )
        elif ready is not None and ready.status == "False":
            sev, title, expl = (
                Severity.HIGH,
                f"Certificate {cr.namespace}/{cr.name} is not ready",
                "cert-manager cannot issue or renew this certificate (issuer, DNS/HTTP challenge or quota problem).",
            )
        else:
            continue
        out.append(
            Finding(
                id=_fid(ref.key, "cert", title.split()[-1]),
                workload=ref,
                category="reliability",
                title=title,
                severity=sev,
                explanation=expl,
                evidence=ev,
                remediations=[
                    RemediationHint(
                        kind="check-certificate",
                        summary=f"kubectl describe certificate -n {cr.namespace} {cr.name}; check the Order/Challenge "
                        "resources and the issuer",
                    )
                ],
            )
        )
    return out


# ---------------------------------------------------------------- edge: ingress-nginx (+ ModSecurity)


def _controller_config(snap: Snapshot, comp: Component) -> dict[str, str] | None:
    for c in comp.containers:
        for arg in c.args:
            if arg.startswith("--configmap="):
                ref = arg.split("=", 1)[1].replace("$(POD_NAMESPACE)", comp.namespace)
                ns, _, name = ref.rpartition("/")
                cm = snap.config_map(ns or comp.namespace, name)
                return dict(cm.data) if cm else None
    return None


def _truthy(v: str | None) -> bool:
    return v is not None and v.strip().strip('"').lower() in ("true", "1", "yes", "on")


def _rule_engine(snippet: str | None) -> str | None:
    if not snippet:
        return None
    m = re.findall(r"^\s*SecRuleEngine\s+(\w+)", snippet, re.M | re.I)
    return m[-1].lower() if m else None


def check_ingress_nginx(snap: Snapshot, comp: Component, comps: list[Component]) -> list[Finding]:
    from kubepilot.engine.components import _finding

    out: list[Finding] = []
    image = next((c.image for c in comp.containers), "")
    ver = _version(image)
    if snap.now >= INGRESS_NGINX_RETIRED:
        out.append(
            _finding(
                comp,
                "retired",
                f"{comp.label}: ingress-nginx is retired and gets no more security fixes",
                Severity.MEDIUM,
                "Kubernetes retired the ingress-nginx project in March 2026: no further releases, bug fixes or fixes "
                "for new vulnerabilities. Existing installs keep working. Plan a migration to the Gateway API or "
                "another maintained ingress controller.",
                category="security",
                evidence=[Evidence(source="image", detail=clean(image, 160))],
                hints=[
                    RemediationHint(
                        kind="plan-migration",
                        summary="Plan migration off ingress-nginx (Gateway API "
                        "implementation or another maintained controller)",
                    )
                ],
            )
        )
    if ver is not None and (ver < (1, 11, 5) or ver == (1, 12, 0)):
        fixed = "v1.11.5" if ver[:2] == (1, 11) else "v1.12.1"
        repo = image.split("@")[0].rsplit(":", 1)[0]
        out.append(
            _finding(
                comp,
                "ingressnightmare",
                f"{comp.label}: controller {'.'.join(map(str, ver))} is vulnerable to IngressNightmare (CVE-2025-1974)",
                Severity.CRITICAL,
                "CVE-2025-1974 (CVSS 9.8) lets anything that can reach the admission webhook run code in the "
                "controller, which can read every Secret in the cluster. Fixed in v1.11.5 and v1.12.1. Until "
                "upgraded, restrict access to the admission webhook with a NetworkPolicy.",
                category="security",
                evidence=[Evidence(source="image", detail=clean(image, 160))],
                hints=[
                    RemediationHint(
                        kind="set-image",
                        params={
                            "container": comp.containers[0].name if comp.containers else "controller",
                            "current": image,
                            "proposed": f"{repo}:{fixed}",
                        },
                        summary=f"Upgrade the controller image to {fixed} or later",
                    )
                ],
            )
        )
    cfg = _controller_config(snap, comp)
    if cfg is not None:
        if _truthy(cfg.get("allow-snippet-annotations")):
            out.append(
                _finding(
                    comp,
                    "snippets",
                    f"{comp.label}: snippet annotations are allowed",
                    Severity.HIGH,
                    "allow-snippet-annotations=true lets anyone who can create an Ingress inject raw NGINX config "
                    "(the root of several ingress-nginx CVEs), e.g. to read the controller's credentials. The "
                    "default is false since v1.9.",
                    category="security",
                    evidence=[Evidence(source="config", detail="allow-snippet-annotations: true")],
                )
            )
        if _truthy(cfg.get("enable-modsecurity")):
            engine = _rule_engine(cfg.get("modsecurity-snippet"))
            mode = "DetectionOnly (the ingress-nginx default)" if engine in (None, "detectiononly") else engine
            shown = engine or "default (DetectionOnly)"
            if engine != "on":
                out.append(
                    _finding(
                        comp,
                        "waf-detect",
                        f"{comp.label}: ModSecurity only detects, it does not block",
                        Severity.MEDIUM,
                        "ModSecurity is enabled but SecRuleEngine is "
                        f"{mode}"
                        ": attacks matching the rules are logged and still reach the apps. Switch to blocking after "
                        "reviewing the audit log for false positives.",
                        category="security",
                        evidence=[
                            Evidence(
                                source="config",
                                detail=f"enable-modsecurity: true, SecRuleEngine: {shown}",
                            )
                        ],
                        hints=[
                            RemediationHint(
                                kind="set-modsecurity-blocking",
                                params={"target_kind": "ConfigMap", "target_name": _cm_name(comp) or ""},
                                summary="Set SecRuleEngine On in the controller's modsecurity-snippet",
                            )
                        ],
                    )
                )
            if not _truthy(cfg.get("enable-owasp-modsecurity-crs")):
                out.append(
                    _finding(
                        comp,
                        "waf-nocrs",
                        f"{comp.label}: ModSecurity runs without the OWASP Core Rule Set",
                        Severity.LOW,
                        "Without enable-owasp-modsecurity-crs the WAF has almost no rules loaded unless custom rules "
                        "are mounted.",
                        category="security",
                    )
                )
            for ing, _hosts in routes_of(snap, comp, comps):
                a = ing.annotations
                off = a.get("nginx.ingress.kubernetes.io/enable-modsecurity", "").lower() == "false"
                eng = _rule_engine(a.get("nginx.ingress.kubernetes.io/modsecurity-snippet"))
                if off or eng in ("off", "detectiononly"):
                    out.append(
                        _finding(
                            comp,
                            f"waf-off-{ing.namespace}-{ing.name}",
                            f"{comp.label}: WAF {'disabled' if off or eng == 'off' else 'set to detect-only'} for "
                            f"Ingress {ing.namespace}/{ing.name}",
                            Severity.MEDIUM,
                            f"Hosts {', '.join(ing.hosts) or '(all)'} bypass blocking even though ModSecurity is on "
                            "for the controller. Often a leftover from debugging a false positive.",
                            category="security",
                        )
                    )
    out += _edge_impact(snap, comp, comps)
    return out


def _cm_name(comp: Component) -> str | None:
    for c in comp.containers:
        for arg in c.args:
            if arg.startswith("--configmap="):
                return arg.split("=", 1)[1].rpartition("/")[2]
    return None


def _edge_impact(snap: Snapshot, comp: Component, comps: list[Component]) -> list[Finding]:
    from kubepilot.engine.components import _finding

    if comp.desired == 0 or comp.ready > 0:
        return []
    routes = routes_of(snap, comp, comps)
    hosts = sorted({h for _, hs in routes for h in hs})
    if not routes:
        return []
    return [
        _finding(
            comp,
            "edge-down",
            f"{comp.label} is down: {len(routes)} Ingress(es) unreachable from outside",
            Severity.CRITICAL,
            "No controller pod is ready, so external traffic for every Ingress it serves fails, even though the "
            "apps behind it may be healthy.",
            evidence=[Evidence(source="ingress", detail=f"hosts: {', '.join(hosts[:10]) or '(no host rules)'}")],
        )
    ]


# ---------------------------------------------------------------- edge: Kong


def check_kong(snap: Snapshot, comp: Component, comps: list[Component]) -> list[Finding]:
    from kubepilot.engine.components import _finding, _labels_match

    out: list[Finding] = []
    exposed = [
        s
        for s in snap.services
        if s.namespace == comp.namespace
        and s.external
        and any(_labels_match(s.selector, p.labels) for p in comp.pods)
        and any(
            p.port in KONG_ADMIN_PORTS
            or (p.target_port or "") in {str(x) for x in KONG_ADMIN_PORTS}
            or (p.name or "").startswith(("kong-admin", "admin", "kong-manager", "manager"))
            for p in s.ports
        )
    ]
    if exposed:
        out.append(
            _finding(
                comp,
                "admin-exposed",
                f"{comp.label}: Admin API / Kong Manager is reachable from outside the cluster",
                Severity.CRITICAL,
                "The Kong Admin API can create routes, plugins and consumers: whoever reaches it controls all "
                "traffic through the gateway (and can read credentials of consumers). Keep it ClusterIP and reach "
                "it with port-forward or behind authentication.",
                category="security",
                evidence=[
                    Evidence(
                        source="service", detail=f"{s.name}: {s.type}, ports {','.join(str(p.port) for p in s.ports)}"
                    )
                    for s in exposed
                ],
                hints=[
                    RemediationHint(
                        kind="make-service-internal",
                        params={"services": ",".join(s.name for s in exposed)},
                        summary="Change the admin Service type to ClusterIP",
                    )
                ],
            )
        )
    listen = next((e.value for c in comp.containers for e in c.env if e.name == "KONG_ADMIN_LISTEN" and e.value), None)
    plain = bool(listen and re.search(r"0\.0\.0\.0:8001(?!\d)(?![^,]*ssl)", listen))
    if plain and comp.pods and not selectors.covering_policies(comp.pods[0], snap.network_policies, "Ingress"):
        out.append(
            _finding(
                comp,
                "admin-plain",
                f"{comp.label}: Admin API listens on all interfaces over plain HTTP",
                Severity.HIGH,
                "KONG_ADMIN_LISTEN binds the Admin API to 0.0.0.0:8001 without TLS and no NetworkPolicy limits "
                "who can connect, so any pod in the cluster can reconfigure the gateway.",
                category="security",
                evidence=[Evidence(source="env", detail="KONG_ADMIN_LISTEN includes 0.0.0.0:8001 (no ssl)")],
            )
        )
    replicas = max(comp.desired, len(comp.pods))
    if replicas > 1:
        for cr in snap.custom_resources:
            if cr.kind not in ("KongPlugin", "KongClusterPlugin"):
                continue
            plugin = str(cr.spec.get("plugin") or "")
            policy = str((cr.spec.get("config") or {}).get("policy") or "local")
            if plugin.startswith("rate-limiting") and plugin != "rate-limiting-advanced" and policy == "local":
                out.append(
                    _finding(
                        comp,
                        f"ratelimit-{cr.namespace}-{cr.name}",
                        f"{comp.label}: rate limit {cr.name} is counted per pod ({replicas} pods)",
                        Severity.LOW,
                        "The rate-limiting plugin with policy local keeps counters in each Kong pod, so clients can "
                        f"send up to {replicas}x the configured limit. Use policy redis (or cluster) for a shared "
                        "limit.",
                        category="config",
                    )
                )
    known = {(c.namespace, c.name) for c in snap.custom_resources if c.kind == "KongPlugin"}
    known_cluster = {c.name for c in snap.custom_resources if c.kind == "KongClusterPlugin"}
    for ing, _ in routes_of(snap, comp, comps):
        for name in [n.strip() for n in ing.annotations.get("konghq.com/plugins", "").split(",") if n.strip()]:
            if (ing.namespace, name) not in known and name not in known_cluster:
                out.append(
                    _finding(
                        comp,
                        f"plugin-missing-{ing.namespace}-{ing.name}-{name}",
                        f"{comp.label}: Ingress {ing.namespace}/{ing.name} references missing KongPlugin {name}",
                        Severity.HIGH,
                        "The policy this route expects (authentication, rate limiting, ...) is not in effect because "
                        f"no KongPlugin or KongClusterPlugin named {name} exists.",
                        category="security",
                    )
                )
    out += _edge_impact(snap, comp, comps)
    return out


# ---------------------------------------------------------------- logging pipeline


def _untolerated_nodes(snap: Snapshot, comp: Component) -> list[str]:
    spec = next((s for s in comp.specs if s.kind == "DaemonSet"), None)
    if spec is None:
        return []
    tol = spec.tolerations

    def tolerated(taint: str) -> bool:
        key_val, _, effect = taint.rpartition(":")
        key = key_val.split("=", 1)[0]
        for t in tol:
            if t.get("operator") == "Exists" and not t.get("key"):
                return True
            if t.get("key") == key and (not t.get("effect") or t.get("effect") == effect):
                return True
        return False

    return [
        n.name
        for n in snap.nodes
        if n.ready and any(t.rsplit(":", 1)[-1] in ("NoSchedule", "NoExecute") and not tolerated(t) for t in n.taints)
    ]


def fluentbit_config(snap: Snapshot, comp: Component) -> tuple[str, list[fluentbit.Section]] | None:
    """(ConfigMap name, parsed sections) of a Fluent Bit component."""
    names = {v.source for s in comp.specs for v in s.template_volumes if v.kind == "configMap" and v.source}
    for p in comp.pods[:1]:
        names |= {v.source for v in p.volumes if v.kind == "configMap" and v.source}
    for name in sorted(names):
        cm = snap.config_map(comp.namespace, name)
        if cm is not None:
            secs = fluentbit.parse(cm.data)
            if secs:
                return name, secs
    return None


def check_logging(snap: Snapshot, comp: Component) -> list[Finding]:
    from kubepilot.engine.components import _finding

    out: list[Finding] = []
    missing = _untolerated_nodes(snap, comp)
    if missing:
        out.append(
            _finding(
                comp,
                "coverage",
                f"{comp.label}: no log collection on {len(missing)} tainted node(s)",
                Severity.MEDIUM,
                "The DaemonSet does not tolerate these nodes' taints, so pods running there have no log agent "
                "and their logs are never shipped (often control-plane or dedicated nodes).",
                category="config",
                evidence=[Evidence(source="nodes", detail=", ".join(missing[:10]))],
                hints=[
                    RemediationHint(
                        kind="add-toleration",
                        params={"operator": "Exists"},
                        summary="Tolerate all taints (operator: Exists), as log agents usually do",
                    )
                ],
            )
        )
    if comp.kind != "fluent-bit":
        return out
    found = fluentbit_config(snap, comp)
    if found is None:
        return out
    cm_name, secs = found
    target = {"target_kind": "ConfigMap", "target_name": cm_name}
    outputs = fluentbit.network_outputs(secs)
    weak = [
        o
        for o in outputs
        if (o.get("retry_limit") or "1").lower() in ("1", "no_retries")
        or ((o.get("retry_limit") or "").isdigit() and int(o.get("retry_limit") or "0") < 3)
    ]
    if weak:
        out.append(
            _finding(
                comp,
                "retry",
                f"{comp.label}: {len(weak)} output(s) drop logs after a single failed retry",
                Severity.MEDIUM,
                "Retry_Limit defaults to 1: when the destination is down or slow for more than one retry, the chunk "
                "is discarded and those logs are lost. Use Retry_Limit False (or a high number) with filesystem "
                "buffering.",
                category="config",
                evidence=[
                    Evidence(
                        source="config",
                        detail=f"[OUTPUT] {o.plugin}: Retry_Limit {o.get('retry_limit') or '(default 1)'}",
                    )
                    for o in weak[:4]
                ],
                hints=[
                    RemediationHint(
                        kind="set-fluentbit-option",
                        params={"section": "output", "key": "Retry_Limit", "value": "False", **target},
                        summary="Set Retry_Limit False on the outputs",
                    )
                ],
            )
        )
    tails = [s for s in secs if s.kind == "input" and s.plugin == "tail"]
    unbounded = [s for s in tails if not s.get("mem_buf_limit") and (s.get("storage.type") or "memory") != "filesystem"]
    if unbounded:
        out.append(
            _finding(
                comp,
                "membuf",
                f"{comp.label}: tail input has no memory limit",
                Severity.MEDIUM,
                "Without Mem_Buf_Limit (or storage.type filesystem) Fluent Bit buffers in memory without bound when "
                "the destination slows down, until the pod is OOM-killed and buffered logs are lost.",
                category="config",
                hints=[
                    RemediationHint(
                        kind="set-fluentbit-option",
                        params={"section": "input:tail", "key": "Mem_Buf_Limit", "value": "50MB", **target},
                        summary="Set Mem_Buf_Limit 50MB on tail inputs",
                    )
                ],
            )
        )
    insecure = []
    for o in outputs:
        host = fluentbit.output_host(o)
        if host and not _in_cluster(snap, host, comp.namespace) and (o.get("tls") or "off").lower() in ("off", "false"):
            insecure.append(f"{o.plugin} -> {host}")
    if insecure:
        out.append(
            _finding(
                comp,
                "tls-off",
                f"{comp.label}: logs leave the cluster unencrypted",
                Severity.MEDIUM,
                "These outputs send logs (which often contain tokens and personal data) to a destination outside the "
                "cluster with TLS off.",
                category="security",
                evidence=[Evidence(source="config", detail=clean(x, 160)) for x in insecure[:4]],
            )
        )
    creds = fluentbit.inline_secrets(secs)
    if creds:
        out.append(
            _finding(
                comp,
                "inline-creds",
                f"{comp.label}: credentials are written in its ConfigMap",
                Severity.LOW,
                "Options " + ", ".join(sorted(set(creds))[:5]) + " hold literal values. Anyone who can read "
                "ConfigMaps can read them; reference environment variables from a Secret (${VAR}) instead.",
                category="security",
            )
        )
    return out


def _in_cluster(snap: Snapshot, host: str, ns: str) -> bool:
    if host.endswith((".svc", ".svc.cluster.local", ".cluster.local")) or "." not in host:
        return True
    parts = host.split(".")
    return any(s.name == parts[0] and s.namespace == parts[1] for s in snap.services if len(parts) >= 2)


def logging_hosts(snap: Snapshot, comp: Component) -> list[tuple[str, str]]:
    """(host, output plugin) pairs from the agent's config, for dependency edges."""
    if comp.kind != "fluent-bit":
        return []
    secs = fluentbit_sections(snap, comp) or []
    out = []
    for o in fluentbit.network_outputs(secs):
        h = fluentbit.output_host(o)
        if h:
            out.append((h, o.plugin))
    return out


def fluentbit_sections(snap: Snapshot, comp: Component) -> list[fluentbit.Section] | None:
    found = fluentbit_config(snap, comp)
    return found[1] if found else None


# ---------------------------------------------------------------- cluster service components


def check_service_component(snap: Snapshot, comp: Component) -> list[Finding]:
    """Kind-specific checks for cluster services (DNS, CNI, mesh, telemetry agents, gateways)."""
    from kubepilot.engine.components import _finding, _labels_match

    out: list[Finding] = []
    if comp.kind == "coredns" and comp.desired == 1:
        out.append(
            _finding(
                comp,
                "dns-single",
                f"{comp.label}: a single replica serves all cluster DNS",
                Severity.MEDIUM,
                "Every pod depends on CoreDNS; with one replica, a node drain or crash breaks name resolution "
                "cluster-wide until it restarts.",
                category="config",
            )
        )
    if comp.kind == "promtail" and snap.now >= PROMTAIL_EOL:
        out.append(
            _finding(
                comp,
                "eol",
                f"{comp.label}: Promtail is end of life (March 2, 2026)",
                Severity.MEDIUM,
                "Grafana ended Promtail support: no fixes or updates, including security fixes. Migrate to Grafana "
                "Alloy (it ships a converter for Promtail configs).",
                category="security",
                hints=[
                    RemediationHint(
                        kind="plan-migration",
                        summary="Migrate Promtail to Grafana Alloy (`alloy convert --source-format=promtail`)",
                    )
                ],
            )
        )
    if comp.kind == "traefik":
        insecure = any("--api.insecure=true" in a or a == "--api.insecure" for c in comp.containers for a in c.args)
        if insecure:
            exposed = [
                s
                for s in snap.services
                if s.namespace == comp.namespace
                and s.external
                and any(_labels_match(s.selector, p.labels) for p in comp.pods)
                and any(p.port == 8080 or p.target_port in ("8080", "traefik") for p in s.ports)
            ]
            out.append(
                _finding(
                    comp,
                    "dashboard",
                    f"{comp.label}: dashboard/API enabled in insecure mode"
                    + (" and exposed outside the cluster" if exposed else ""),
                    Severity.CRITICAL if exposed else Severity.MEDIUM,
                    "--api.insecure=true serves the Traefik dashboard and API on the `traefik` entrypoint (port 8080) "
                    "without authentication, revealing every route, backend and middleware."
                    + (" A LoadBalancer/NodePort Service publishes it." if exposed else ""),
                    category="security",
                    evidence=[Evidence(source="service", detail=f"{s.name}: {s.type}") for s in exposed],
                    hints=[
                        RemediationHint(
                            kind="make-service-internal",
                            params={"services": ",".join(s.name for s in exposed)},
                            summary="Make the dashboard Service internal",
                        )
                    ]
                    if exposed
                    else [],
                )
            )
    return out
