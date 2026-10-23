"""Live backend logic without a cluster: pagination, kind injection, missing CRDs, normalization of
real client objects (V1Pod etc. serialized exactly as the API would return them)."""

from __future__ import annotations

from typing import Any

import pytest
from kubernetes import client
from kubernetes.client.exceptions import ApiException

from kubepilot.source.kube import KubeSource


def _bare() -> KubeSource:
    ks = object.__new__(KubeSource)
    ks._api = client.ApiClient()
    ks._alerts = None
    ks._cache = {}
    ks._cache_ttl = 0
    return ks


def _pod(name: str) -> client.V1Pod:
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name=name, namespace="ns", labels={"app": "a"}),
        spec=client.V1PodSpec(containers=[client.V1Container(name="c", image="img:1")]),
        status=client.V1PodStatus(phase="Running"),
    )


def test_pagination_and_kind_injection() -> None:
    ks = _bare()
    pages = {
        None: client.V1PodList(items=[_pod("a")], metadata=client.V1ListMeta(_continue="tok")),
        "tok": client.V1PodList(items=[_pod("b")], metadata=client.V1ListMeta()),
    }
    calls: list[Any] = []

    def fake_list(limit: int, _continue: str | None = None, **kw: Any) -> client.V1PodList:
        calls.append((limit, _continue, kw))
        return pages[_continue]

    out = ks._list(fake_list, "Pod", namespace="ns")
    assert [o["metadata"]["name"] for o in out] == ["a", "b"]
    assert all(o["kind"] == "Pod" for o in out)
    assert calls[0][2] == {"namespace": "ns"} and calls[1][1] == "tok"
    # camelCase API shape, as normalize expects
    assert out[0]["spec"]["containers"][0]["image"] == "img:1"


class _Custom:
    def __init__(self, status: int | None) -> None:
        self.status = status

    def list_cluster_custom_object(self, *a: Any) -> dict[str, Any]:
        if self.status:
            raise ApiException(status=self.status)
        return {"items": [{"metadata": {"name": "r"}}]}

    list_namespaced_custom_object = list_cluster_custom_object


@pytest.mark.parametrize("status", [403, 404])
def test_missing_trivy_crd_is_a_warning(status: int) -> None:
    ks = _bare()
    ks._custom = _Custom(status)
    warnings: list[str] = []
    assert ks._trivy(None, warnings) == []
    assert "Trivy" in warnings[0]


def test_trivy_items_get_kind() -> None:
    ks = _bare()
    ks._custom = _Custom(None)
    items = ks._trivy("ns", [])
    assert items[0]["kind"] == "VulnerabilityReport"


def test_other_api_errors_propagate() -> None:
    ks = _bare()
    ks._custom = _Custom(500)
    with pytest.raises(ApiException):
        ks._trivy(None, [])
