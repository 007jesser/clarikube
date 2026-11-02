"""Client-facing audit report: turn clarikube's findings into a branded, print-ready HTML document (and a PDF
when a converter is installed).

    clarikube report --client "ACME GmbH" --out acme.html --pdf

The report is one self-contained HTML file (no external assets, no network), laid out for A4 so any browser
prints it cleanly to PDF. Content comes entirely from the read-only analysis; nothing is invented here.
"""

from __future__ import annotations

import html
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LAYER_TITLES = {
    "edge": "Edge & ingress",
    "data": "Data systems",
    "logging": "Logging pipeline",
    "network": "Networking",
    "mesh": "Service mesh",
    "gitops": "GitOps",
    "secrets": "Secrets",
    "tls": "Certificates & TLS",
    "policy": "Admission policy",
    "autoscaling": "Autoscaling",
    "storage": "Storage",
    "backup": "Backups",
    "monitoring": "Monitoring",
    "cloud": "Nodes & cloud",
}


@dataclass
class ReportMeta:
    client: str
    cluster: str
    prepared_by: str
    contact: str
    source: str
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))


def _grade(sev_counts: dict[str, int]) -> tuple[str, str]:
    """A plain letter grade a non-technical reader understands, from the worst severities present."""
    c, h, m = sev_counts.get("critical", 0), sev_counts.get("high", 0), sev_counts.get("medium", 0)
    if c:
        return "E", "Critical issues need action now"
    if h >= 3:
        return "D", "Several serious issues to fix soon"
    if h:
        return "C", "Serious issues to plan for"
    if m:
        return "B", "Minor issues, broadly healthy"
    return "A", "No significant issues found"


def build_report(kp: Any, meta: ReportMeta) -> dict[str, Any]:
    """Collect everything the report needs from the service. Read-only."""
    health = kp.cluster_health()
    problems = kp.find_problems(None, "low")
    security = kp.security_triage()

    findings = sorted(problems.get("findings", []), key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    incidents = sorted(security.get("incidents", []), key=lambda i: -i.get("score", 0))
    grade, grade_note = _grade(sev_counts)

    # top risks in plain words: worst reliability finding per workload + worst security incidents
    top: list[dict[str, str]] = []
    seen: set[str] = set()
    for f in findings:
        if f["severity"] in ("critical", "high") and f["workload"] not in seen:
            seen.add(f["workload"])
            top.append({"title": f["title"], "where": f["workload"], "severity": f["severity"]})
        if len(top) >= 6:
            break

    return {
        "meta": meta,
        "grade": grade,
        "grade_note": grade_note,
        "sev_counts": sev_counts,
        "cluster": {
            "nodes": health.get("nodes", {}),
            "workloads": health.get("workloads"),
            "pods": health.get("pods"),
            "as_of": health.get("as_of"),
            "warnings": health.get("warnings", []),
        },
        "top_risks": top,
        "incidents": incidents,
        "findings": findings,
        "platform_issues": sorted(
            health.get("platform_issues", []), key=lambda p: SEVERITY_ORDER.get(p["severity"], 9)
        ),
        "components": health.get("components", []),
        "capacity": health.get("capacity"),
        "scoring_note": security.get("scoring", ""),
    }


# ----------------------------------------------------------------- rendering

_CSS = """
:root{--ink:#1a2332;--muted:#5b6b82;--line:#e2e8f0;--bg:#fff;
--crit:#b91c1c;--high:#c2410c;--med:#a16207;--low:#2563eb;--ok:#15803d;}
*{box-sizing:border-box} html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font:14px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
margin:0;background:#f1f5f9}
.page{background:var(--bg);max-width:820px;margin:24px auto;padding:48px 56px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.5px}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:20px 0 6px}
.sub{color:var(--muted);font-size:13px}
.cover{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid var(--ink);padding-bottom:18px}
.brand{font-weight:700;font-size:15px}.brand span{color:var(--muted);font-weight:400}
.meta-grid{display:grid;grid-template-columns:auto 1fr;gap:4px 18px;margin:18px 0;font-size:13px}
.meta-grid div:nth-child(odd){color:var(--muted)}
.hero{display:flex;gap:24px;align-items:center;margin:24px 0;padding:20px;background:#f8fafc;border:1px solid var(--line);border-radius:10px}
.grade{font-size:54px;font-weight:800;width:92px;height:92px;display:flex;align-items:center;justify-content:center;
border-radius:14px;color:#fff;flex:none}
.g-A{background:var(--ok)}.g-B{background:#4d7c0f}.g-C{background:var(--med)}.g-D{background:var(--high)}.g-E{background:var(--crit)}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.pill{font-size:12px;font-weight:600;padding:3px 10px;border-radius:20px;border:1px solid}
.pill.crit{color:var(--crit);border-color:var(--crit)}.pill.high{color:var(--high);border-color:var(--high)}
.pill.med{color:var(--med);border-color:var(--med)}.pill.low{color:var(--low);border-color:var(--low)}
.badge{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;padding:2px 7px;border-radius:4px;color:#fff}
.b-critical{background:var(--crit)}.b-high{background:var(--high)}.b-medium{background:var(--med)}.b-low{background:var(--low)}
.finding{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:7px;padding:13px 16px;margin:10px 0;break-inside:avoid}
.finding.critical{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}.finding.low{border-left-color:var(--low)}
.finding .head{display:flex;justify-content:space-between;gap:12px;align-items:baseline}
.finding .ttl{font-weight:650;font-size:14.5px}
.finding .where{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted)}
.finding p{margin:7px 0 0;font-size:13px}
.ev{margin:8px 0 0;padding:8px 12px;background:#f8fafc;border-radius:6px;font-size:12.5px}
.ev div{margin:2px 0}.ev .k{color:var(--muted);font-family:ui-monospace,monospace;font-size:11px}
.fix{margin-top:8px;font-size:13px;padding:7px 12px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px}
.fix b{color:var(--ok)}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px}
.mono{font-family:ui-monospace,monospace}
.note{font-size:12px;color:var(--muted);margin:6px 0}
.layer-h{font-size:13px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin:18px 0 2px}
footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted)}
@media print{body{background:#fff}.page{box-shadow:none;margin:0;max-width:none;padding:14mm 16mm}h2{break-after:avoid}}
"""


def _e(s: Any) -> str:
    return html.escape(str(s))


def _finding_html(f: dict[str, Any]) -> str:
    sev = f["severity"]
    parts = [f'<div class="finding {sev}"><div class="head">']
    parts.append(f'<span class="ttl">{_e(f["title"])}</span>')
    parts.append(f'<span class="badge b-{sev}">{sev}</span></div>')
    parts.append(f'<div class="where">{_e(f["workload"])}</div>')
    if f.get("explanation"):
        parts.append(f"<p>{_e(f['explanation'])}</p>")
    ev = f.get("evidence") or []
    if ev:
        parts.append('<div class="ev">')
        for e in ev[:4]:
            parts.append(
                f'<div><span class="k">{_e(e.get("source", ""))}</span> &middot; {_e(e.get("detail", ""))}</div>'
            )
        parts.append("</div>")
    rems = [r for r in (f.get("remediations") or []) if r.get("summary")]
    if rems:
        auto = next((r for r in rems if r.get("automatable")), None)
        r = auto or rems[0]
        label = "Fix available as a GitOps change" if r.get("automatable") else "Recommended action"
        parts.append(f'<div class="fix"><b>{label}:</b> {_e(r["summary"])}</div>')
    parts.append("</div>")
    return "".join(parts)


def render_html(rep: dict[str, Any]) -> str:
    m: ReportMeta = rep["meta"]
    sc = rep["sev_counts"]
    nodes = rep["cluster"]["nodes"] or {}

    counts_html = (
        "".join(
            f'<span class="pill {k[:4]}">{v} {k}</span>'
            for k, v in (
                ("crit", sc.get("critical", 0)),
                ("high", sc.get("high", 0)),
                ("med", sc.get("medium", 0)),
                ("low", sc.get("low", 0)),
            )
            if v
        )
        or '<span class="pill low">no issues above low severity</span>'
    )

    top = (
        "".join(
            f'<tr><td><span class="badge b-{r["severity"]}">{r["severity"]}</span></td>'
            f'<td>{_e(r["title"])}</td><td class="mono">{_e(r["where"])}</td></tr>'
            for r in rep["top_risks"]
        )
        or '<tr><td colspan="3" class="note">No critical or high-severity reliability risks found.</td></tr>'
    )

    # findings grouped by category then layer-ish: reliability first, then config, then security handled separately
    rel = [f for f in rep["findings"] if f["category"] == "reliability"]
    cfg = [f for f in rep["findings"] if f["category"] == "config"]
    secf = [f for f in rep["findings"] if f["category"] == "security"]

    def block(items: list[dict[str, Any]]) -> str:
        return "".join(_finding_html(f) for f in items) if items else '<p class="note">None found.</p>'

    # incidents
    inc_html = []
    for i in rep["incidents"][:10]:
        sev = i["severity"]
        inc_html.append(f'<div class="finding {sev}"><div class="head">')
        inc_html.append(f'<span class="ttl">{_e(i["workload"])}</span>')
        inc_html.append(f'<span class="badge b-{sev}">score {i["score"]} &middot; {sev}</span></div>')
        inc_html.append(f"<p>{_e(i['summary'])}</p>")
        sigs = i.get("signals") or []
        if sigs:
            inc_html.append('<div class="ev">' + "".join(f"<div>&bull; {_e(s)}</div>" for s in sigs[:6]) + "</div>")
        inc_html.append("</div>")
    incidents_block = (
        "".join(inc_html) or '<p class="note">No security incidents scored above the reporting threshold.</p>'
    )

    # platform issues table
    plat = "".join(
        f'<tr><td><span class="badge b-{p["severity"]}">{p["severity"]}</span></td>'
        f"<td>{_e(p.get('area', ''))}</td><td>{_e(p['title'])}</td></tr>"
        for p in rep["platform_issues"][:30]
    )
    plat_block = (
        f"<table><tr><th>Severity</th><th>Area</th><th>Issue</th></tr>{plat}</table>"
        if plat
        else '<p class="note">No platform-level issues found.</p>'
    )

    # capacity
    cap = rep.get("capacity")
    cap_block = ""
    if cap:
        cpu, mem = cap.get("cpu", {}), cap.get("memory", {})
        cap_block = (
            f"<table><tr><th>Resource</th><th>Requested</th><th>In use</th><th>Idle (paid, unused)</th></tr>"
            f"<tr><td>CPU</td><td>{cpu.get('requested_m', '?')}m</td><td>{cpu.get('used_m', '?')}m</td>"
            f"<td>{cpu.get('idle_requested_m', '?')}m</td></tr>"
            f"<tr><td>Memory</td><td>{_e(mem.get('requested', '?'))}</td><td>{_e(mem.get('used', '?'))}</td>"
            f"<td>{_e(mem.get('idle_requested', '?'))}</td></tr></table>"
            f'<p class="note">{_e(cap.get("note", ""))}</p>'
        )

    # components
    comp = "".join(
        f'<tr><td><span class="badge b-{"critical" if c["status"] == "down" else ("high" if c["status"] == "at-risk" else "low")}">'
        f"{_e(c['status'])}</span></td><td>{_e(c['component'])}</td><td>{_e(LAYER_TITLES.get(c['layer'], c['layer']))}</td>"
        f"<td>{c.get('issues', 0)}</td><td>{_e(c.get('top_issue', ''))}</td></tr>"
        for c in rep["components"]
    )
    comp_block = (
        f"<table><tr><th>Status</th><th>Component</th><th>Layer</th><th>Issues</th><th>Main problem</th></tr>{comp}</table>"
        if comp
        else '<p class="note">No managed platform components detected.</p>'
    )

    warn = ""
    if rep["cluster"]["warnings"]:
        warn = (
            '<p class="note"><b>Data-collection notes:</b> '
            + "; ".join(_e(w) for w in rep["cluster"]["warnings"])
            + "</p>"
        )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kubernetes Health &amp; Security Report — {_e(m.client)}</title><style>{_CSS}</style></head><body>
<div class="page">
  <div class="cover">
    <div>
      <h1>Kubernetes Health &amp; Security Report</h1>
      <div class="sub">Prepared for <b>{_e(m.client)}</b></div>
    </div>
    <div class="brand" style="text-align:right">clarikube<br><span>read-only audit</span></div>
  </div>
  <div class="meta-grid">
    <div>Cluster</div><div>{_e(m.cluster)}</div>
    <div>Date</div><div>{_e(m.generated_at)}</div>
    <div>Prepared by</div><div>{_e(m.prepared_by)} &middot; {_e(m.contact)}</div>
    <div>Scope</div><div>{_e(nodes.get("total", "?"))} node(s), {_e(rep["cluster"]["workloads"])} workloads, {_e(rep["cluster"]["pods"])} pods</div>
    <div>Method</div><div>Read-only inspection of Kubernetes state. No changes were made to the cluster.</div>
  </div>

  <div class="hero">
    <div class="grade g-{rep["grade"]}">{rep["grade"]}</div>
    <div>
      <div style="font-weight:700;font-size:16px">{_e(rep["grade_note"])}</div>
      <div class="counts">{counts_html}</div>
    </div>
  </div>

  <h2>Executive summary</h2>
  <p>This report is the result of an automated, read-only inspection of the <b>{_e(m.client)}</b> Kubernetes cluster.
  It lists what is broken or at risk, why it matters, and how to fix it. Findings are produced by deterministic
  checks with evidence &mdash; not guesses &mdash; and every fix can be delivered as a reviewed change to your
  configuration, so nothing is applied to the cluster without your approval.</p>
  <h3>Top risks</h3>
  <table><tr><th>Severity</th><th>Risk</th><th>Where</th></tr>{top}</table>

  <h2>Security</h2>
  <p>Workloads are scored by combining runtime alerts, image vulnerabilities, excessive privileges and exposure,
  and missing network isolation. Higher score = more urgent.</p>
  {incidents_block}
  <p class="note">{_e(rep["scoring_note"])}</p>

  <h2>Reliability &amp; root causes</h2>
  <p>Failures are traced to their real cause across layers (an app failing because a data system or dependency it
  relies on is unhealthy), so you fix the source rather than the symptom.</p>
  {block(rel)}

  <h2>Configuration &amp; hardening</h2>
  {block(cfg)}

  {"<h2>Additional security findings</h2>" + block(secf) if secf else ""}

  <h2>Platform components</h2>
  {comp_block}

  <h2>Routing, certificates &amp; platform issues</h2>
  {plat_block}

  {"<h2>Capacity &amp; cost</h2>" + cap_block if cap_block else ""}

  <h2>Method &amp; scope</h2>
  <p>clarikube read the cluster's state through the Kubernetes API using a <b>read-only</b> identity. It cannot
  create, change or delete resources, and does not read Secret contents. Environment values and config data are
  processed in memory and never stored or reproduced in this report (only names are shown). This is a
  configuration and state review: it does not connect to your applications or run live traffic tests.</p>
  {warn}

  <footer>
    Generated by clarikube &mdash; Kubernetes health &amp; security audit. &copy; {datetime.now(UTC):%Y} {_e(m.prepared_by)}.
    This report reflects the cluster state at the time of capture ({_e(rep["cluster"].get("as_of") or m.generated_at)}).
  </footer>
</div></body></html>"""


def to_pdf(html_path: Path, pdf_path: Path) -> str | None:
    """Convert with whatever converter is installed. Returns the tool used, or None if none is available."""
    if shutil.which("wkhtmltopdf"):
        subprocess.run(
            ["wkhtmltopdf", "--enable-local-file-access", "-q", "-s", "A4", str(html_path), str(pdf_path)],
            check=True,
            capture_output=True,
        )
        return "wkhtmltopdf"
    for browser in ("chromium", "chromium-browser", "google-chrome"):
        if shutil.which(browser):
            subprocess.run(
                [
                    browser,
                    "--headless",
                    "--no-sandbox",
                    "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf_path}",
                    f"file://{html_path.resolve()}",
                ],
                check=True,
                capture_output=True,
            )
            return browser
    try:
        import weasyprint  # type: ignore

        weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return "weasyprint"
    except Exception:
        return None
