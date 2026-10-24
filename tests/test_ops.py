"""Cluster operations packs: gateways, GitOps controllers, secrets, autoscaling, storage, policy, backups,
monitoring/alerts, nodes, load balancers, mesh, cluster services and metrics-server usage."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from kubepilot.engine import layers, ops, usage
from kubepilot.service import KubePilot
from kubepilot.source.alerts import AlertStore, make_ingest_app
from kubepilot.source.base import Snapshot


def titles(findings: list) -> set[str]:  # type: ignore[type-arg]
    return {f.title for f in findings}


def test_gateway_api_and_traefik(snap: Snapshot) -> None:
    t = titles(ops.gateway_findings(snap))
    assert "Gateway shop/public is not serving traffic" in t
    assert "Gateway shop/public: listener https is broken" in t
    assert "HTTPRoute data/reviews is not attached to Gateway public" in t
    assert "HTTPRoute data/reviews: backend reference cannot be resolved" in t
    assert "IngressRoute shop/admin uses missing Middleware basic-auth" in t
    assert any("IngressRoute shop/admin routes" in x and "admin-ui" in x for x in t)


def test_gitops_controllers(snap: Snapshot) -> None:
    fs = ops.gitops_findings(snap)
    by = {f.title: f for f in fs}
    sync = by["Argo CD app data-tier: sync is failing"]
    assert any("immutable" in e.detail for e in sync.evidence)
    assert "Argo CD app legacy-cms is OutOfSync (manual sync)" in by
    assert "Flux Kustomization flux-system/platform is failing" in by
    assert any("knownhosts" in e.detail for e in by["Flux GitRepository flux-system/infra is failing"].evidence)
    assert "Flux HelmRelease monitoring/grafana is suspended" in by


def test_secret_sync_is_named_as_root_cause(kp: KubePilot) -> None:
    fs = kp.diagnose_workload("shop", "api")["findings"]
    assert fs[0]["title"] == "Likely root cause: ExternalSecret shop/api-db-credentials is failing to sync"
    assert any("permission denied" in e["detail"] for e in fs[0]["evidence"])
    t = titles(ops.secret_findings(kp._snap(None)))
    assert "SealedSecret shop/payment-keys cannot be decrypted" in t


def test_autoscaling(kp: KubePilot) -> None:
    t = titles(ops.autoscaling_findings(kp._snap(None)))
    assert "HPA checkout cannot read its metrics and is not scaling" in t
    assert "HPA frontend is pinned at maxReplicas (1)" in t
    assert "KEDA ScaledObject shop/worker-queue is not ready" in t
    assert "Karpenter NodePool default reached its cpu limit" in t
    assert "Karpenter NodeClaim default-x7k2p failed to launch" in t
    worker = [f["title"] for f in kp.diagnose_workload("shop", "worker")["findings"]]
    assert "Cluster Autoscaler will not add a node for worker" in worker


def test_storage_explains_pending_kafka_broker(kp: KubePilot) -> None:
    snap = kp._snap(None)
    t = titles(ops.storage_findings(snap))
    assert "PVC data/data-events-broker-2 uses missing StorageClass fast-ssd" in t
    assert "Longhorn volume pvc-4f1c2a9e is degraded" in t
    kafka = kp.diagnose_component("data", "events")["findings"]
    vol = next(f for f in kafka if "volume data-events-broker-2" in f["title"])
    assert "fast-ssd does not exist" in vol["explanation"]


def test_policy_denial_and_reports(kp: KubePilot) -> None:
    rec = kp.diagnose_workload("shop", "recommendations")  # a Deployment with zero pods is still diagnosable
    assert rec["findings"][0]["title"] == "Pods of recommendations are blocked by admission policy"
    assert "require-run-as-nonroot" in rec["findings"][0]["evidence"][0]["detail"]
    t = titles(ops.policy_findings(kp._snap(None)))
    assert "Deployment shop/payment-api fails 1 policy check(s)" in t


def test_backups_monitoring_alerts(snap: Snapshot) -> None:
    t = titles(ops.backup_findings(snap))
    assert "Velero backup location default is unavailable" in t
    assert "Velero schedule daily: last backup PartiallyFailed" in t
    assert "Velero schedule daily: no backup for 10 days" in t
    assert "Alertmanager monitoring/main is not available" in titles(ops.monitoring_findings(snap))
    alerts = {f.title: f for f in ops.alert_findings(snap)}
    assert alerts["Alert firing: KubePodCrashLooping"].workload.key == "Deployment/shop/orders"
    assert "Alert firing: Watchdog" not in alerts  # pipeline heartbeat, not a problem
    assert not any("KubeCPUOvercommit" in t for t in alerts)  # resolved


def test_nodes_lb_mesh(snap: Snapshot) -> None:
    t = titles(ops.cluster_findings(snap))
    assert "Node kind-worker2: kubelet is more than 3 minor versions behind" in t
    assert "LoadBalancer Service shop/partner-api has no external address" in t
    assert not any("traefik" in x for x in t if "LoadBalancer" in x)  # has an address
    assert "details-v1 runs without the Istio sidecar in a meshed namespace" in t
    assert "ratings-v1: istio-proxy sidecar is not ready" in t


def test_cluster_services(kp: KubePilot) -> None:
    rows = {r["component"]: r for r in kp.list_components()["components"]}
    assert rows["Cilium kube-system/cilium"]["layer"] == "network"
    cil = kp.diagnose_component("kube-system", "cilium")["findings"]
    assert any("lose networking" in f["explanation"] for f in cil)
    dns = [f["title"] for f in kp.diagnose_component("kube-system", "coredns")["findings"]]
    assert any("single replica serves all cluster DNS" in t for t in dns)
    prom = [f["title"] for f in kp.diagnose_component("logging", "promtail")["findings"]]
    assert any("end of life" in t for t in prom)
    tr = [f["title"] for f in kp.diagnose_component("kube-system", "traefik")["findings"]]
    assert any("insecure mode and exposed outside the cluster" in t for t in tr)


@pytest.mark.parametrize(
    ("image", "kind"),
    [
        ("rancher/mirrored-library-traefik:3.3.6", "traefik"),
        ("quay.io/argoproj/argocd:v3.1.0", "argocd"),
        ("ghcr.io/fluxcd/kustomize-controller:v1.6.0", "flux"),
        ("oci.external-secrets.io/external-secrets/external-secrets:v0.18.0", "external-secrets"),
        ("docker.io/bitnami/sealed-secrets-controller:0.30.0", "sealed-secrets"),
        ("registry.k8s.io/coredns/coredns:v1.12.0", "coredns"),
        ("quay.io/cilium/cilium:v1.17.4", "cilium"),
        ("docker.io/istio/pilot:1.26.1", "istio"),
        ("docker.io/grafana/alloy:v1.9.0", "alloy"),
        ("otel/opentelemetry-collector-contrib:0.128.0", "otel-collector"),
        ("velero/velero:v1.16.1", "velero"),
        ("public.ecr.aws/karpenter/controller:1.5.0", "karpenter"),
        ("registry.k8s.io/autoscaling/cluster-autoscaler:v1.33.0", "cluster-autoscaler"),
    ],
)
def test_catalog_images(image: str, kind: str) -> None:
    assert layers.classify_platform_image(image) == kind


def test_usage_oom_risk_and_capacity(kp: KubePilot) -> None:
    snap = kp._snap(None)
    fs = {f.title: f for f in usage.usage_findings(snap)}
    risk = fs["'proxy' is at 95% of its memory limit (OOM risk)"]
    assert risk.workload.key == "Deployment/kong/kong-gateway"
    assert risk.remediations[0].params["proposed"] == "1536Mi"
    assert "'payment-api' is using its whole CPU limit (throttled)" in fs
    assert any(t.startswith("'rabbitmq' requests 1Gi memory") for t in fs)
    cap = kp.cluster_health()["capacity"]
    assert cap["memory"]["used"] and "metrics-server" in cap["note"]


def test_cluster_health_groups_platform_issues(kp: KubePilot) -> None:
    areas = {r["area"] for r in kp.cluster_health()["platform_issues"]}
    assert {
        "routing",
        "tls",
        "gitops",
        "secrets",
        "autoscaling",
        "storage",
        "backup",
        "monitoring",
        "alerts",
        "nodes",
    } <= areas


def test_alertmanager_webhook_ingest(tmp_path: Path) -> None:
    from starlette.testclient import TestClient

    store = AlertStore(tmp_path / "a.db")
    client = TestClient(make_ingest_app(store, token="t"))
    payload = {
        "version": "4",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HighErrorRate",
                    "namespace": "shop",
                    "deployment": "api",
                    "severity": "critical",
                },
                "annotations": {"summary": "5xx above 5%"},
                "startsAt": "2026-10-23T09:00:00Z",
                "fingerprint": "f1",
            }
        ],
    }
    assert client.post("/alertmanager", json=payload).status_code == 401
    r = client.post("/alertmanager", json=payload, headers={"Authorization": "Bearer t"})
    assert r.json() == {"stored": 1}
    since = datetime.now(UTC) - timedelta(minutes=5)
    assert [a.name for a in store.firing(since)] == ["HighErrorRate"]
    payload["alerts"][0]["status"] = "resolved"
    client.post("/alertmanager", json=payload, headers={"Authorization": "Bearer t"})
    assert store.firing(since) == []  # resolution replaces the firing state


def test_no_secret_material_in_outputs(kp: KubePilot) -> None:
    blob = json.dumps([kp.cluster_health(), kp.find_problems(min_severity="low")])
    for needle in ("AgB4xKZ", "DEMO-not-a-real-password", "sk_live"):
        assert needle not in blob
