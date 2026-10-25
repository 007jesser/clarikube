"""Edit Helm values in a GitOps repo when the workload itself is rendered by Helm.

Charts name their values differently, so kubemedic never guesses a path from the chart name. It finds the
values that belong to the release (Argo CD ``helm.valuesObject`` / ``valueFiles``, Flux ``HelmRelease``
``spec.values``, or a ``values*.yaml`` in a directory named after the release) and then edits only a value
whose *current* content matches what is live in the cluster. Zero or several matches => refuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml as pyyaml
from ruamel.yaml.comments import CommentedMap

from kubemedic import quantity
from kubemedic.gitops import manifests as mf

KeyPath = tuple[str | int, ...]


@dataclass
class ValuesTarget:
    path: Path  # relative to repo root
    index: int  # document index (0 for plain values files)
    keypath: KeyPath  # where the values mapping lives inside the document; () for a values file
    source: str  # human description

    def describe(self) -> str:
        where = ".".join(str(k) for k in self.keypath)
        return f"{self.path}" + (f"#{self.index} {where}" if where else "")


def _load(f: Path) -> list[Any]:
    try:
        return list(pyyaml.safe_load_all(f.read_text()))
    except (pyyaml.YAMLError, UnicodeDecodeError):
        return []


def _yaml_files(root: Path) -> list[Path]:
    out = []
    for f in sorted(root.rglob("*.y*ml")):
        rel = f.relative_to(root)
        if any(p in {".git", "node_modules", ".github"} for p in rel.parts) or f.stat().st_size > mf.MAX_FILE_BYTES:
            continue
        out.append(f)
    return out


def locate_values(root: Path, release: str, namespace: str) -> list[ValuesTarget]:
    found: list[ValuesTarget] = []
    for f in _yaml_files(root):
        rel = f.relative_to(root)
        for i, d in enumerate(_load(f)):
            if not isinstance(d, dict):
                continue
            kind, api = d.get("kind"), str(d.get("apiVersion", ""))
            meta = d.get("metadata") or {}
            spec = d.get("spec") or {}
            if kind == "Application" and api.startswith("argoproj.io/"):
                dest_ns = (spec.get("destination") or {}).get("namespace")
                if dest_ns not in (None, namespace):
                    continue
                sources: list[tuple[KeyPath, dict[str, Any]]] = []
                if isinstance(spec.get("source"), dict):
                    sources.append((("spec", "source"), spec["source"]))
                sources += [
                    (("spec", "sources", n), s) for n, s in enumerate(spec.get("sources") or []) if isinstance(s, dict)
                ]
                for base, src in sources:
                    helm = src.get("helm") or {}
                    if (helm.get("releaseName") or meta.get("name")) != release:
                        continue
                    if isinstance(helm.get("valuesObject"), dict):
                        found.append(ValuesTarget(rel, i, (*base, "helm", "valuesObject"), "Argo CD valuesObject"))
                    for vf in helm.get("valueFiles") or []:
                        cand = (root / str(src.get("path") or "") / str(vf)).resolve()
                        if cand.is_file() and root.resolve() in cand.parents:
                            found.append(ValuesTarget(cand.relative_to(root.resolve()), 0, (), "Argo CD valueFiles"))
            elif kind == "HelmRelease" and api.startswith("helm.toolkit.fluxcd.io/"):
                name = spec.get("releaseName") or meta.get("name")
                ns = spec.get("targetNamespace") or meta.get("namespace")
                if name == release and ns in (None, namespace) and isinstance(spec.get("values"), dict):
                    found.append(ValuesTarget(rel, i, ("spec", "values"), "Flux HelmRelease values"))
        if f.name.startswith("values") and f.parent.name == release:
            found.append(ValuesTarget(rel, 0, (), "values file"))
    # The same file can be found twice (Argo valueFiles + directory name): dedupe.
    uniq: dict[tuple[str, int, KeyPath], ValuesTarget] = {}
    for t in found:
        uniq.setdefault((str(t.path), t.index, t.keypath), t)
    return list(uniq.values())


def _walk(node: Any, path: KeyPath = ()) -> list[tuple[KeyPath, Any]]:
    out: list[tuple[KeyPath, Any]] = [(path, node)]
    if isinstance(node, dict):
        for k, v in node.items():
            out += _walk(v, (*path, str(k)))
    elif isinstance(node, list):
        for n, v in enumerate(node):
            out += _walk(v, (*path, n))
    return out


def _mem_eq(a: Any, b: str) -> bool:
    try:
        return quantity.parse(str(a)) == quantity.parse(b)
    except (ValueError, ArithmeticError):
        return str(a) == b


def memory_paths(values: Any, section: str, current: str | None) -> list[KeyPath]:
    """Paths of ``resources.<section>.memory`` entries whose value equals ``current`` (or all of them)."""
    hits = []
    for path, node in _walk(values):
        if len(path) >= 1 and path[-1] == "resources" and isinstance(node, dict):
            sec = node.get(section)
            if isinstance(sec, dict) and "memory" in sec and (current is None or _mem_eq(sec["memory"], current)):
                hits.append((*path, section, "memory"))
    return hits


def image_paths(values: Any, current: str) -> list[tuple[KeyPath, str]]:
    """Where the live image is set: a full string equal to it, or a {repository, tag} map with the same tag."""
    repo_part, _, tag = current.rpartition(":")
    if "/" in tag:  # "host:5000/img" has no tag
        repo_part, tag = current, ""
    last = repo_part.rsplit("/", 1)[-1]
    hits: list[tuple[KeyPath, str]] = []
    for path, node in _walk(values):
        if isinstance(node, str) and node == current:
            hits.append((path, "full"))
        elif isinstance(node, dict) and "tag" in node and tag and str(node.get("tag")) == tag:
            r = str(node.get("repository") or node.get("name") or "")
            if r and r.rsplit("/", 1)[-1] == last:
                hits.append(((*path, "tag"), "tag"))
    return hits


def get_in(node: Any, path: KeyPath) -> Any:
    for k in path:
        node = node[k]
    return node


def set_in(node: Any, path: KeyPath, value: Any) -> Any:
    parent = get_in(node, path[:-1])
    old = parent[path[-1]]
    parent[path[-1]] = value
    return old


def values_root(ef: mf.EditableFile, target: ValuesTarget) -> CommentedMap:
    doc = ef.docs[target.index]
    return get_in(doc, target.keypath) if target.keypath else doc  # type: ignore[no-any-return]


def fmt(path: KeyPath) -> str:
    return ".".join(str(p) for p in path)
