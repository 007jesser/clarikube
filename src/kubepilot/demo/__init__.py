"""Bundled demo data: a synthetic broken cluster, a matching GitOps repo and an allowlist.

Shipped inside the package so `uvx kubepilot demo` works without cloning the repository.
"""

from __future__ import annotations

from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
CLUSTER = DEMO_DIR / "cluster"
GITOPS_REPO = DEMO_DIR / "gitops-repo"
ALLOWLIST = DEMO_DIR / "allowlist.yaml"
