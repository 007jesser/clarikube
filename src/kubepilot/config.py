"""Configuration from environment variables (12-factor; no secrets in files)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Literal


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    source: Literal["kube", "fixture"]
    fixture_dir: Path | None
    kube_context: str | None
    alerts_db: Path | None
    allowlist: Path | None
    gitops_repo: Path | None
    state_dir: Path
    dry_run: bool
    push: bool
    approval_mode: Literal["token", "cli"]
    plan_ttl: timedelta
    falco_window: timedelta
    ingest_token: str | None
    system_namespaces: frozenset[str] = frozenset(
        {"kube-system", "kube-public", "kube-node-lease", "falco", "trivy-system"}
    )

    @classmethod
    def from_env(cls) -> Settings:
        src = os.environ.get("KUBEPILOT_SOURCE", "kube")
        if src not in ("kube", "fixture"):
            raise ValueError("KUBEPILOT_SOURCE must be 'kube' or 'fixture'")
        mode = os.environ.get("KUBEPILOT_APPROVAL_MODE", "token")
        if mode not in ("token", "cli"):
            raise ValueError("KUBEPILOT_APPROVAL_MODE must be 'token' or 'cli'")

        def path(name: str) -> Path | None:
            v = os.environ.get(name)
            return Path(v).expanduser() if v else None

        state = path("KUBEPILOT_STATE_DIR") or Path.home() / ".local" / "state" / "kubepilot"
        return cls(
            source=src,  # type: ignore[arg-type]
            fixture_dir=path("KUBEPILOT_FIXTURE_DIR"),
            kube_context=os.environ.get("KUBEPILOT_KUBE_CONTEXT") or None,
            alerts_db=path("KUBEPILOT_ALERTS_DB"),
            allowlist=path("KUBEPILOT_ALLOWLIST"),
            gitops_repo=path("KUBEPILOT_GITOPS_REPO"),
            state_dir=state,
            dry_run=_bool("KUBEPILOT_DRY_RUN", True),
            push=_bool("KUBEPILOT_GITOPS_PUSH", False),
            approval_mode=mode,  # type: ignore[arg-type]
            plan_ttl=timedelta(minutes=int(os.environ.get("KUBEPILOT_PLAN_TTL_MINUTES", "30"))),
            falco_window=timedelta(hours=int(os.environ.get("KUBEPILOT_FALCO_WINDOW_HOURS", "24"))),
            ingest_token=os.environ.get("KUBEPILOT_INGEST_TOKEN") or None,
            **(
                {"system_namespaces": frozenset(n.strip() for n in sysns.split(",") if n.strip())}
                if (sysns := os.environ.get("KUBEPILOT_SYSTEM_NAMESPACES")) is not None
                else {}
            ),
        )
