from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from clarikube import demo
from clarikube.config import Settings
from clarikube.service import Clarikube
from clarikube.source.base import Snapshot
from clarikube.source.fixture import FixtureSource

ROOT = Path(__file__).resolve().parents[1]

DEMO = demo.CLUSTER
GITOPS = demo.GITOPS_REPO
ALLOWLIST = demo.ALLOWLIST


@pytest.fixture(scope="session")
def demo_source() -> FixtureSource:
    return FixtureSource(DEMO)


@pytest.fixture
def snap(demo_source: FixtureSource) -> Snapshot:
    return demo_source.snapshot()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def gitops_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(GITOPS, repo)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    return repo


def make_settings(tmp_path: Path, repo: Path | None, **over: object) -> Settings:
    from datetime import timedelta

    base: dict[str, object] = dict(
        source="fixture",
        fixture_dir=DEMO,
        kube_context=None,
        alerts_db=None,
        allowlist=ALLOWLIST,
        gitops_repo=repo,
        state_dir=tmp_path / "state",
        dry_run=False,
        push=False,
        approval_mode="token",
        plan_ttl=timedelta(minutes=30),
        falco_window=timedelta(hours=24),
        ingest_token=None,
        read_logs=True,  # fixture default: bundled demo logs
    )
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def kp(tmp_path: Path, gitops_repo: Path, demo_source: FixtureSource) -> Clarikube:
    return Clarikube(demo_source, make_settings(tmp_path, gitops_repo))
