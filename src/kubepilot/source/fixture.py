"""Fixture backend: loads a captured/synthetic cluster from a directory of YAML files.

Layout::

    <dir>/meta.yaml          # {now: "2026-10-23T10:00:00Z"}  (optional; default: real now)
    <dir>/*.yaml             # Kubernetes objects; multi-doc and `kind: List` supported
    <dir>/falco.jsonl        # Falco JSON events, one per line (optional)

Useful for demos, tests, and for capturing a real cluster with ``kubepilot capture``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from kubepilot import normalize
from kubepilot.source.base import LOG_LIMIT_BYTES, RawCluster, Snapshot
from kubepilot.source.crds import CR_GROUPS

_KIND_FIELD = {
    "Pod": "pods",
    "ReplicaSet": "replicasets",
    "Job": "jobs",
    "Event": "events",
    "Node": "nodes",
    "NetworkPolicy": "network_policies",
    "Role": "roles",
    "ClusterRole": "roles",
    "RoleBinding": "bindings",
    "ClusterRoleBinding": "bindings",
    "VulnerabilityReport": "vulnerability_reports",
    "Deployment": "workloads",
    "StatefulSet": "workloads",
    "DaemonSet": "workloads",
    "PersistentVolumeClaim": "pvcs",
    "Service": "services",
    "PodDisruptionBudget": "pdbs",
}
_CLUSTER_SCOPED = {"Node", "ClusterRole", "ClusterRoleBinding"}


def _iter_objects(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    if doc.get("kind", "").endswith("List") and isinstance(doc.get("items"), list):
        out: list[dict[str, Any]] = []
        for item in doc["items"]:
            out.extend(_iter_objects(item))
        return out
    return [doc]


class FixtureSource:
    name = "fixture"

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        if not self.dir.is_dir():
            raise FileNotFoundError(f"fixture directory not found: {self.dir}")
        self._raw = RawCluster()
        self._now = datetime.now(UTC)
        self._load()

    def _load(self) -> None:
        meta = self.dir / "meta.yaml"
        if meta.exists():
            data = yaml.safe_load(meta.read_text()) or {}
            if data.get("now"):
                self._now = normalize.ts(data["now"]) or self._now
        for f in sorted(self.dir.glob("*.yaml")):
            if f.name == "meta.yaml":
                continue
            for doc in yaml.safe_load_all(f.read_text()):
                for obj in _iter_objects(doc):
                    attr = _KIND_FIELD.get(obj.get("kind", ""))
                    if attr is None and str(obj.get("apiVersion", "")).split("/")[0] in CR_GROUPS:
                        attr = "custom_resources"
                    if attr:
                        getattr(self._raw, attr).append(obj)
        self._falco = []
        falco = self.dir / "falco.jsonl"
        if falco.exists():
            for line in falco.read_text().splitlines():
                if line.strip():
                    self._falco.append(normalize.falco_alert(json.loads(line)))

    def logs(self, namespace: str, pod: str, container: str, previous: bool) -> str | None:
        """Demo logs live in ``logs/<pod>__<container>.log`` (namespace is implied by the unique pod name)."""
        f = self.dir / "logs" / f"{pod}__{container}.log"
        if "/" in pod + container or not f.is_file():
            return None
        return f.read_bytes()[-LOG_LIMIT_BYTES:].decode("utf-8", "replace")

    def snapshot(self, namespace: str | None = None) -> Snapshot:
        raw = self._raw
        if namespace:
            raw = RawCluster(
                **{
                    attr: [
                        o
                        for o in getattr(self._raw, attr)
                        if o.get("kind") in _CLUSTER_SCOPED
                        or (o.get("metadata") or {}).get("namespace") == namespace
                        or (
                            o.get("kind") == "VulnerabilityReport"
                            and ((o.get("metadata") or {}).get("labels") or {}).get("trivy-operator.resource.namespace")
                            == namespace
                        )
                    ]
                    for attr in RawCluster.__dataclass_fields__
                }
            )
        falco = [a for a in self._falco if not namespace or a.namespace == namespace]
        return Snapshot.build(raw, now=self._now, falco=falco)
