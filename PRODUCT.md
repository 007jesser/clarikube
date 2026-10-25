# clarikube — product tiers

clarikube is **open core**: a free, open-source engine that earns trust, and a paid layer that
teams buy for the things that save them time or satisfy an operational requirement — never for
access to a model.

## Core — open source (Apache-2.0)

The analysis engine and everything an engineer needs to try it, read the code, and trust it.

- MCP server + CLI, model-agnostic
- **Read-only** toward the cluster; minimal read-only ClusterRole
- Deterministic, evidence-backed checks across every layer (apps, data, edge, logging, TLS, mesh,
  GitOps, secrets, autoscaling, storage, policy, backups, monitoring)
- Root-cause tracing across dependencies
- Security triage (Falco + Trivy + RBAC + NetworkPolicy), scored and explained
- Fixes as GitOps changes for one repo, behind plan → diff → approval
- Single-run report (HTML/PDF)
- Local-model `ask`, demo, capture

**Goal:** adoption. People run it, inspect it, share it with their team.

## Pro — commercial (separate private package `clarikube-pro`)

Builds on Core through its public API. Priced on capabilities that save a team time or meet a
requirement.

| Capability | Why a team pays | Status |
|---|---|---|
| **History & trends** | snapshots over time: grade trend, MTTR, "is it improving?" | ✅ in scaffold |
| **What-changed diff** | new vs resolved findings since the last scan | ✅ in scaffold |
| **Continuous scanning + alerts** | scheduled runs; Slack/email/PagerDuty on regressions | next |
| **Team dashboard (web UI)** | multi-cluster fleet view, not a terminal | planned |
| **GitHub/GitLab app** | fixes as PRs with status checks and in-platform approval | planned |
| **Audit trail + SSO** | who approved which change — compliance needs this | planned |
| **Policy packs** | curated CIS / SOC 2 / PCI bundles + custom org rules | planned |
| **Scheduled & branded multi-client reports** | the consultant mode: one command per client | planned |
| **Priority support / SLA** | a number to call | ongoing |

**Goal:** revenue, feature-by-feature, built when a paying customer asks.

## Why this split works

- **Core stays permissive (Apache-2.0)** so Pro can be built closed on top of it. AGPL would force
  Pro open — wrong for open core.
- **Pro is a separate private repo**, depends on Core as a normal package, and plugs in through
  Core's public API (`clarikube.service.Clarikube`, `clarikube.report`). No fork, no Core code
  copied into Pro.
- The heavy, trust-building intelligence is in Core, visible and testable. Pro is the operational
  layer around it.

## Sequencing (do not build Pro speculatively)

1. **Core → public, free.** Trust and inbound interest.
2. **Earn with the service now.** The single-run report in Core already powers a paid audit,
   delivered by hand. First revenue needs no Pro code.
3. **Build Pro one feature at a time**, starting with history + continuous scanning + alerts —
   the first thing teams actually ask to pay for.
