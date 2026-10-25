"""Parse Fluent Bit configuration (classic ``.conf`` and YAML) into sections, in memory only.

Values can hold credentials (``HTTP_Passwd``, cloud keys), so callers must only report option *names*,
plugin names and destination hosts, never values. Only what the checks need is understood:
``[INPUT]``/``[OUTPUT]``/``[SERVICE]`` sections, ``@INCLUDE`` of other keys in the same ConfigMap,
and the YAML ``service`` / ``pipeline.inputs`` / ``pipeline.outputs`` layout.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

_SECTION = re.compile(r"^\s*\[(\w+)\]\s*$")
_INCLUDE = re.compile(r"^\s*@INCLUDE\s+(\S+)", re.I)
_SECRET_KEYS = re.compile(r"passw|secret|token|api_?key|access_key|private_key|sas_token|shared_key", re.I)


@dataclass
class Section:
    kind: str  # input | output | service | filter | parser
    options: dict[str, str] = field(default_factory=dict, repr=False)  # lower-cased keys

    @property
    def plugin(self) -> str:
        return self.options.get("name", "").lower()

    def get(self, key: str) -> str | None:
        return self.options.get(key.lower())


def _classic(text: str, files: dict[str, str], depth: int = 0) -> list[Section]:
    out: list[Section] = []
    current: Section | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        inc = _INCLUDE.match(stripped)
        if inc:
            ref = inc.group(1).rsplit("/", 1)[-1]
            if depth < 3 and ref in files:
                out += _classic(files[ref], files, depth + 1)
            continue
        m = _SECTION.match(stripped)
        if m:
            current = Section(kind=m.group(1).lower())
            out.append(current)
            continue
        if current is not None:
            parts = stripped.split(None, 1)
            if parts:
                current.options[parts[0].lower()] = parts[1].strip() if len(parts) > 1 else ""
    return out


def _yaml(text: str) -> list[Section]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    out: list[Section] = []
    if isinstance(doc.get("service"), dict):
        out.append(Section("service", {str(k).lower(): str(v) for k, v in doc["service"].items()}))
    pipeline = doc.get("pipeline") or {}
    if isinstance(pipeline, dict):
        for key, kind in (("inputs", "input"), ("outputs", "output"), ("filters", "filter")):
            for item in pipeline.get(key) or []:
                if isinstance(item, dict):
                    out.append(Section(kind, {str(k).lower(): _flat(v) for k, v in item.items()}))
    return out


def _flat(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def parse(files: dict[str, str]) -> list[Section]:
    """Sections from a ConfigMap's files. Picks the main file (fluent-bit.conf / fluent-bit.yaml) when present."""
    main: str | None = next((n for n in ("fluent-bit.yaml", "fluent-bit.yml", "fluent-bit.conf") if n in files), None)
    if main is None:
        main = next((n for n in files if n.endswith((".conf", ".yaml", ".yml"))), None)
    if main is None:
        return []
    text = files[main]
    return _yaml(text) if main.endswith((".yaml", ".yml")) else _classic(text, files)


def inline_secrets(sections: list[Section]) -> list[str]:
    """Option names whose values look like literal credentials (not ${ENV} references)."""
    names = []
    for s in sections:
        for k, v in s.options.items():
            if _SECRET_KEYS.search(k) and v and not v.strip().startswith("${"):
                names.append(f"{s.plugin or s.kind}.{k}")
    return names


_NO_NETWORK = {"stdout", "null", "file", "counter", "flowcounter", "exit"}


def network_outputs(sections: list[Section]) -> list[Section]:
    return [s for s in sections if s.kind == "output" and s.plugin not in _NO_NETWORK]


def output_host(s: Section) -> str | None:
    host = s.get("host")
    if not host or host.startswith("${"):
        return None
    return host.strip().lower().rstrip(".")


# ---------------------------------------------------------------- editing (for GitOps fixes)


def _matches(kind: str, plugin: str, selector: str) -> bool:
    """selector: "output" (network outputs) or "input:tail" (inputs of one plugin)."""
    want_kind, _, want_plugin = selector.partition(":")
    if kind != want_kind:
        return False
    if want_plugin:
        return plugin == want_plugin
    return not (kind == "output" and plugin in _NO_NETWORK)


def set_option_classic(text: str, selector: str, key: str, value: str) -> tuple[str, int]:
    """Set ``key value`` in every matching section of a classic config. Returns (new text, sections changed)."""
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    out: list[str] = []
    changed = 0
    i = 0
    while i < len(lines):
        m = _SECTION.match(lines[i].strip())
        if not m:
            out.append(lines[i])
            i += 1
            continue
        j = i + 1
        while j < len(lines) and not _SECTION.match(lines[j].strip()) and not _INCLUDE.match(lines[j].strip()):
            j += 1
        body = lines[i + 1 : j]
        out.append(lines[i])
        opts: dict[str, int] = {}
        for k, ln in enumerate(body):
            parts = ln.split(None, 1)
            if parts and not parts[0].startswith("#"):
                opts[parts[0].lower()] = k
        name_idx = opts.get("name")
        plugin = (
            body[name_idx].split(None, 1)[1].strip().lower()
            if name_idx is not None and len(body[name_idx].split(None, 1)) > 1
            else ""
        )
        if _matches(m.group(1).lower(), plugin, selector):
            ref = next((ln for ln in body if ln.strip()), "    x")
            indent = ref[: len(ref) - len(ref.lstrip())]
            new_line = f"{indent}{key} {value}\n"
            idx = opts.get(key.lower())
            if idx is not None:
                current = body[idx].split(None, 1)[1].strip() if len(body[idx].split(None, 1)) > 1 else ""
                if current != value:
                    body[idx] = new_line
                    changed += 1
            else:
                last = max((n for n, ln in enumerate(body) if ln.strip()), default=-1)
                body.insert(last + 1, new_line)
                changed += 1
        out.extend(body)
        i = j
    return "".join(out), changed
