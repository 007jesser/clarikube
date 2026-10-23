"""Find and edit workload manifests in a GitOps repo, preserving comments and formatting."""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml as pyyaml
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from kubepilot.models import WorkloadRef

# (mapping, sequence, offset) indentation styles seen in the wild, tried in order.
_STYLES = [(2, 4, 2), (2, 2, 0)]
_SKIP_DIRS = {".git", "node_modules", "charts", ".github"}
MAX_FILE_BYTES = 1024 * 1024


def _yaml(style: tuple[int, int, int]) -> YAML:
    y = YAML(typ="rt")
    y.preserve_quotes = True
    y.width = 4096
    y.indent(mapping=style[0], sequence=style[1], offset=style[2])
    return y


@dataclass
class ManifestDoc:
    path: Path  # relative to repo root
    index: int  # document index in a multi-doc file
    kind: str
    name: str
    namespace: str | None  # explicit metadata.namespace, or from kustomization
    namespace_source: str  # "metadata" | "kustomization" | "none"


def _kustomize_namespace(file: Path, root: Path) -> str | None:
    """Nearest kustomization.yaml (walking up to the repo root) that sets ``namespace``."""
    d = file.parent
    while True:
        for name in ("kustomization.yaml", "kustomization.yml", "Kustomization"):
            k = d / name
            if k.exists():
                try:
                    data = pyyaml.safe_load(k.read_text()) or {}
                except pyyaml.YAMLError:
                    data = {}
                if isinstance(data, dict) and data.get("namespace"):
                    return str(data["namespace"])
        if d == root or root not in d.parents:
            return None
        d = d.parent


def scan(root: Path) -> list[ManifestDoc]:
    """Index every parseable Kubernetes object in the repo (Helm templates are skipped)."""
    out: list[ManifestDoc] = []
    for f in sorted(root.rglob("*.y*ml")):
        rel = f.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts) or f.stat().st_size > MAX_FILE_BYTES:
            continue
        if f.name.startswith("kustomization"):
            continue
        try:
            docs = list(pyyaml.safe_load_all(f.read_text()))
        except (pyyaml.YAMLError, UnicodeDecodeError):
            continue  # templated (Helm) or invalid — not editable in v1
        for i, d in enumerate(docs):
            if not isinstance(d, dict) or "kind" not in d or not isinstance(d.get("metadata"), dict):
                continue
            meta = d["metadata"]
            ns, src = meta.get("namespace"), "metadata"
            if not ns:
                ns = _kustomize_namespace(f, root)
                src = "kustomization" if ns else "none"
            out.append(ManifestDoc(rel, i, str(d["kind"]), str(meta.get("name", "")), ns, src))
    return out


def locate(root: Path, wl: WorkloadRef) -> list[ManifestDoc]:
    """Candidate manifests for a workload. Exact namespace matches win over namespace-less ones."""
    docs = [d for d in scan(root) if d.kind == wl.kind and d.name == wl.name]
    exact = [d for d in docs if d.namespace == wl.namespace]
    if exact:
        return exact
    return [d for d in docs if d.namespace is None]


# ---------------------------------------------------------------- round-trip editing


class EditableFile:
    """A multi-doc YAML file loaded for round-trip editing."""

    def __init__(self, root: Path, rel: Path) -> None:
        self.root = root
        self.rel = rel
        self.original = (root / rel).read_text()
        self.style = _STYLES[0]
        self.style_preserved = False
        for style in _STYLES:
            docs = list(_yaml(style).load_all(self.original))
            if self._dump(docs, style) == self.original:
                self.style, self.style_preserved = style, True
                break
        self.docs: list[Any] = list(_yaml(self.style).load_all(self.original))

    def _dump(self, docs: list[Any], style: tuple[int, int, int]) -> str:
        buf = io.StringIO()
        _yaml(style).dump_all(docs, buf)
        out = buf.getvalue()
        # ruamel emits "---" only between docs; keep a leading marker if the original had one.
        if self.original.lstrip().startswith("---") and not out.startswith("---"):
            out = "---\n" + out
        return out

    def render(self) -> str:
        return self._dump(self.docs, self.style)


def pod_spec(doc: CommentedMap) -> CommentedMap:
    kind = doc.get("kind")
    spec = doc.get("spec")
    if kind == "Pod":
        return spec  # type: ignore[no-any-return]
    if kind == "CronJob":
        return spec["jobTemplate"]["spec"]["template"]["spec"]  # type: ignore[no-any-return]
    return spec["template"]["spec"]  # type: ignore[no-any-return]


def container(doc: CommentedMap, name: str) -> CommentedMap:
    for c in pod_spec(doc).get("containers") or []:
        if c.get("name") == name:
            return c  # type: ignore[no-any-return]
    raise KeyError(f"container {name!r} not found in manifest")


def ensure_map(parent: CommentedMap, key: str, before: str | None = None) -> CommentedMap:
    """Get ``parent[key]`` as a map, creating it (optionally positioned before key ``before``)."""
    if not isinstance(parent.get(key), dict):
        if before is not None and before in parent and key not in parent:
            parent.insert(list(parent.keys()).index(before), key, CommentedMap())
        else:
            parent[key] = CommentedMap()
    return parent[key]  # type: ignore[no-any-return]


def dump_new(obj: Any) -> str:
    """Serialize a new object in the conventional k8s style used by most repos."""
    buf = io.StringIO()
    _yaml(_STYLES[0]).dump(obj, buf)
    return buf.getvalue()


def to_plain(node: Any) -> Any:
    """ruamel nodes -> plain Python (for policy checks)."""
    if isinstance(node, dict):
        return {str(k): to_plain(v) for k, v in node.items()}
    if isinstance(node, (list, CommentedSeq)):
        return [to_plain(v) for v in node]
    return node
