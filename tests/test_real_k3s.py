"""Regression tests from a real k3s lab capture (v1.36, Oct 2026). Every assertion here is a bug the bundled
synthetic demo did not catch."""

from __future__ import annotations

from pathlib import Path

import pytest

from kubemedic.engine import components as C
from kubemedic.engine import diagnose
from kubemedic.source.base import Snapshot
from kubemedic.source.fixture import FixtureSource

FIXTURE = Path(__file__).parent / "fixtures" / "k3s-lab-2026-10"


@pytest.fixture(scope="module")
def real() -> Snapshot:
    return FixtureSource(FIXTURE).snapshot()


def test_crash_between_backoffs_is_detected(real: Snapshot) -> None:
    # kubectl showed "Error" (terminated, exit 1, 3 restarts) rather than CrashLoopBackOff at capture time
    wl = real.find_workload("shop", "reports")
    assert wl is not None
    titles = [f.title for f in diagnose.diagnose_workload(real, wl)]
    assert "CrashLoopBackOff: 'reports' keeps exiting (code 1)" in titles


def test_startup_probe_noise_is_ignored_once_ready(real: Snapshot) -> None:
    # CoreDNS / metrics-server failed readiness for a few seconds after a VM reboot, 30 min before capture
    for name in ("coredns", "metrics-server"):
        wl = real.find_workload("kube-system", name)
        assert wl is not None
        assert not any("probe" in f.title.lower() for f in diagnose.diagnose_workload(real, wl))


def test_k3s_mirrored_images_are_recognised(real: Snapshot) -> None:
    kinds = {c.kind for c in C.detect(real)}
    assert {"coredns", "metrics-server"} <= kinds


def test_server_version_from_capture_meta(real: Snapshot) -> None:
    assert real.server_version == "v1.36.5+k3s1"
