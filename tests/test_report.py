"""Client report: structure, grading, redaction and that it renders from the demo cluster."""

from __future__ import annotations

import json

from clarikube.report import ReportMeta, build_report, render_html
from clarikube.service import Clarikube


def _meta() -> ReportMeta:
    return ReportMeta(
        client="ACME GmbH", cluster="prod-eu-1", prepared_by="Jesser", contact="j@example.com", source="fixture"
    )


def test_report_structure_and_grade(kp: Clarikube) -> None:
    rep = build_report(kp, _meta())
    assert set(rep) >= {"grade", "sev_counts", "top_risks", "incidents", "findings", "platform_issues", "components"}
    # the demo cluster has critical issues, so the grade is the worst band
    assert rep["grade"] == "E"
    assert rep["sev_counts"].get("critical", 0) > 0
    assert rep["top_risks"]  # at least one top risk surfaced
    # top risks are only critical/high and deduped by workload
    wls = [r["where"] for r in rep["top_risks"]]
    assert len(wls) == len(set(wls))
    assert all(r["severity"] in ("critical", "high") for r in rep["top_risks"])


def test_report_html_renders_and_is_self_contained(kp: Clarikube) -> None:
    rep = build_report(kp, _meta())
    out = render_html(rep)
    assert out.startswith("<!doctype html>")
    assert "ACME GmbH" in out and "Health &amp; Security Report" in out
    assert "<style>" in out  # CSS is inlined
    assert "http://" not in out and "https://" not in out  # no external assets or links
    # grade badge is present
    assert 'class="grade g-E"' in out


def test_report_never_leaks_config_values(kp: Clarikube) -> None:
    rep = build_report(kp, _meta())
    blob = json.dumps({k: v for k, v in rep.items() if k != "meta"}, default=str) + render_html(rep)
    assert "DEMO-not-a-real-password" not in blob  # config/env values are names-only everywhere


def test_report_html_escapes_client_name(kp: Clarikube) -> None:
    m = _meta()
    m.client = "<script>alert(1)</script> Ltd"
    out = render_html(build_report(kp, m))
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;" in out
