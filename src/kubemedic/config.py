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
    read_logs: bool = False
    system_namespaces: frozenset[str] = frozenset(
        {"kube-system", "kube-public", "kube-node-lease", "falco", "trivy-system"}
    )

    @classmethod
    def from_env(cls) -> Settings:
        src = os.environ.get("KUBEMEDIC_SOURCE", "kube")
        if src not in ("kube", "fixture"):
            raise ValueError("KUBEMEDIC_SOURCE must be 'kube' or 'fixture'")
        mode = os.environ.get("KUBEMEDIC_APPROVAL_MODE", "token")
        if mode not in ("token", "cli"):
            raise ValueError("KUBEMEDIC_APPROVAL_MODE must be 'token' or 'cli'")

        def path(name: str) -> Path | None:
            v = os.environ.get(name)
            return Path(v).expanduser() if v else None

        state = path("KUBEMEDIC_STATE_DIR") or Path.home() / ".local" / "state" / "kubemedic"
        return cls(
            source=src,  # type: ignore[arg-type]
            fixture_dir=path("KUBEMEDIC_FIXTURE_DIR"),
            kube_context=os.environ.get("KUBEMEDIC_KUBE_CONTEXT") or None,
            alerts_db=path("KUBEMEDIC_ALERTS_DB"),
            allowlist=path("KUBEMEDIC_ALLOWLIST"),
            gitops_repo=path("KUBEMEDIC_GITOPS_REPO"),
            state_dir=state,
            dry_run=_bool("KUBEMEDIC_DRY_RUN", True),
            push=_bool("KUBEMEDIC_GITOPS_PUSH", False),
            approval_mode=mode,  # type: ignore[arg-type]
            plan_ttl=timedelta(minutes=int(os.environ.get("KUBEMEDIC_PLAN_TTL_MINUTES", "30"))),
            falco_window=timedelta(hours=int(os.environ.get("KUBEMEDIC_FALCO_WINDOW_HOURS", "24"))),
            ingest_token=os.environ.get("KUBEMEDIC_INGEST_TOKEN") or None,
            # Fixture logs are bundled demo data; real cluster logs are opt-in (needs pods/log RBAC).
            read_logs=_bool("KUBEMEDIC_READ_LOGS", src == "fixture"),
            **(
                {"system_namespaces": frozenset(n.strip() for n in sysns.split(",") if n.strip())}
                if (sysns := os.environ.get("KUBEMEDIC_SYSTEM_NAMESPACES")) is not None
                else {}
            ),
        )
