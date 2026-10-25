"""Platform layers: edge (ingress-nginx + ModSecurity, Kong), log pipeline (Fluent Bit), routing, certificates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kubemedic.engine import components as C
from kubemedic.engine import fluentbit, layers
from kubemedic.service import Kubemedic
from kubemedic.source.base import Snapshot


def titles(kp: Kubemedic, ns: str, name: str) -> list[str]:
    return [f["title"] for f in kp.diagnose_component(ns, name)["findings"]]


@pytest.mark.parametrize(
    ("image", "kind"),
    [
        ("registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:abc", "ingress-nginx"),
        ("kong:3.9", "kong"),
        ("kong/kong-gateway:3.9.1.0", "kong"),
        ("kong/kubernetes-ingress-controller:3.4", None),  # the controller is not the gateway
        ("cr.fluentbit.io/fluent/fluent-bit:3.2.2", "fluent-bit"),
        ("fluent/fluentd-kubernetes-daemonset:v1.17", "fluentd"),
        ("timberio/vector:0.43.0-debian", "vector"),
        ("nginx:1.27", None),
    ],
)
def test_classify_platform_images(image: str, kind: str | None) -> None:
    assert layers.classify_platform_image(image) == kind


def test_platform_components_detected_with_layers(snap: Snapshot) -> None:
    by = {c.key: c for c in C.detect(snap)}
    assert by["ingress-nginx/ingress-nginx/ingress-nginx"].layer == "edge"
    assert by["kong/kong/kong"].layer == "edge"
    fb = by["fluent-bit/logging/fluent-bit"]
    assert fb.layer == "logging" and fb.specs[0].kind == "DaemonSet" and len(fb.pods) == 2


def test_ingress_nginx_checks(kp: Kubemedic) -> None:
    t = titles(kp, "ingress-nginx", "ingress-nginx")
    assert any("vulnerable to IngressNightmare (CVE-2025-1974)" in x for x in t)
    assert any("snippet annotations are allowed" in x for x in t)
    assert any("retired" in x for x in t)
    assert any("ModSecurity only detects" in x for x in t)
    assert any("WAF disabled for Ingress shop/storefront" in x for x in t)
    d = kp.diagnose_component("ingress-nginx", "ingress-nginx")
    assert d["routes"] == [{"ingress": "shop/storefront", "hosts": ["shop.example.com"]}]


def test_ingressnightmare_version_boundaries() -> None:
    assert layers._version("registry.k8s.io/ingress-nginx/controller:v1.12.1@sha256:x") == (1, 12, 1)
    vulnerable = [(1, 9, 6), (1, 11, 4), (1, 12, 0)]
    fixed = [(1, 11, 5), (1, 12, 1), (1, 13, 0)]
    assert all(v < (1, 11, 5) or v == (1, 12, 0) for v in vulnerable)
    assert not any(v < (1, 11, 5) or v == (1, 12, 0) for v in fixed)


def test_kong_checks(kp: Kubemedic) -> None:
    t = titles(kp, "kong", "kong-gateway")
    assert any("Admin API / Kong Manager is reachable from outside" in x for x in t)
    assert any("listens on all interfaces over plain HTTP" in x for x in t)
    assert any("references missing KongPlugin key-auth" in x for x in t)
    assert any("rate limit rate-limit is counted per pod (2 pods)" in x for x in t)
    assert not any("missing KongPlugin rate-limit" in x for x in t)


def test_fluent_bit_checks_and_pipeline(kp: Kubemedic) -> None:
    d = kp.diagnose_component("logging", "fluent-bit")
    t = [f["title"] for f in d["findings"]]
    assert any("no log collection on 1 tainted node" in x for x in t)
    assert any("drop logs after a single failed retry" in x for x in t)
    assert any("tail input has no memory limit" in x for x in t)
    assert any("logs leave the cluster unencrypted" in x for x in t)
    assert any("credentials are written in its ConfigMap" in x for x in t)
    assert any("logs are not being delivered to OpenSearch data/search (down)" in x for x in t)
    assert d["ships_to"] == [{"component": "OpenSearch data/search", "service": "search", "output": "opensearch"}]
    assert "DEMO-not-a-real-password" not in json.dumps(d)  # config values are never returned


def test_routing_and_certificates(kp: Kubemedic) -> None:
    rows = kp.cluster_health()["platform_issues"]
    got = {r["title"] for r in rows}
    assert "Ingress shop/storefront: shop.example.com/ has no ready backend (frontend)" in got
    assert "Ingress shop/storefront routes shop.example.com/checkout to missing Service checkout-svc" in got
    assert "Ingress shop/orders-api: api.example.com/orders has no ready backend (orders)" in got
    assert any(t.startswith("Certificate shop/shop-tls expires in") for t in got)
    cert = next(f for f in kp.find_problems()["findings"] if f["workload"] == "Certificate/shop/shop-tls")
    assert any("rateLimited" in e["detail"] for e in cert["evidence"])


def test_workload_view_shows_user_impact(kp: Kubemedic) -> None:
    titles_ = [f["title"] for f in kp.diagnose_workload("shop", "frontend")["findings"]]
    assert any(t.startswith("Users affected: Ingress shop/storefront") for t in titles_)


def test_fluentbit_parser_classic_yaml_and_includes() -> None:
    classic = {
        "fluent-bit.conf": "[SERVICE]\n    Flush 1\n@INCLUDE out.conf\n",
        "out.conf": "[OUTPUT]\n    Name es\n    Host es.logging.svc\n    HTTP_Passwd s3cret\n",
    }
    secs = fluentbit.parse(classic)
    assert [s.kind for s in secs] == ["service", "output"]
    assert fluentbit.output_host(secs[1]) == "es.logging.svc"
    assert fluentbit.inline_secrets(secs) == ["es.http_passwd"]
    y = {"fluent-bit.yaml": "pipeline:\n  outputs:\n    - name: loki\n      host: loki.mon\n      retry_limit: false\n"}
    ysecs = fluentbit.parse(y)
    assert ysecs[0].plugin == "loki" and ysecs[0].get("retry_limit") == "false"


def test_fluentbit_set_option_is_idempotent() -> None:
    text = "[INPUT]\n    Name tail\n\n[OUTPUT]\n    Name stdout\n\n[OUTPUT]\n    Name es\n    Retry_Limit 1\n"
    once, n1 = fluentbit.set_option_classic(text, "output", "Retry_Limit", "False")
    twice, n2 = fluentbit.set_option_classic(once, "output", "Retry_Limit", "False")
    assert (n1, n2) == (1, 0) and once == twice
    assert "Name stdout\n\n" in once  # non-network outputs are left alone
    tail, n3 = fluentbit.set_option_classic(text, "input:tail", "Mem_Buf_Limit", "50MB")
    assert n3 == 1 and "    Mem_Buf_Limit 50MB\n" in tail


# ---------------------------------------------------------------- fixes


def test_plan_ingress_nginx_upgrade_and_waf(kp: Kubemedic) -> None:
    p = kp.plan_remediation("ingress-nginx", "ingress-nginx", ["set-image"])
    assert "+          image: registry.k8s.io/ingress-nginx/controller:v1.11.5" in p["files"][0]["diff"]
    w = kp.plan_remediation("ingress-nginx", "ingress-nginx", ["set-modsecurity-blocking"])
    assert "+  modsecurity-snippet: |" in w["files"][0]["diff"] and "SecRuleEngine On" in w["files"][0]["diff"]
    assert any("false positives" in n for n in w["notes"])


def test_plan_kong_admin_internal(kp: Kubemedic) -> None:
    p = kp.plan_remediation("kong", "kong-gateway", ["make-service-internal"])
    d = p["files"][0]["diff"]
    assert "+  type: ClusterIP" in d and "-      nodePort: 32001" in d


def test_plan_fluent_bit_merges_edits_into_one_file(kp: Kubemedic, gitops_repo: Path) -> None:
    p = kp.plan_remediation("logging", "fluent-bit")
    assert [f["path"] for f in p["files"]] == ["platform/logging/fluent-bit.yaml"]
    d = p["files"][0]["diff"]
    assert d.count("+        Retry_Limit False") == 2
    assert "+        Mem_Buf_Limit 50MB" in d and "+        - operator: Exists" in d
    kp.commit_plan(p["id"], p["approval_token"])  # one coherent commit, no overwritten edits


def test_select_one_option_by_exact_key(kp: Kubemedic) -> None:
    p = kp.plan_remediation("logging", "fluent-bit", ["set-fluentbit-option:Mem_Buf_Limit"])
    assert "Mem_Buf_Limit" in p["files"][0]["diff"] and "Retry_Limit" not in p["files"][0]["diff"]
