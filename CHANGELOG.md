# Changelog

## 0.1.0 (unreleased)
First public alpha.
- Diagnosis engine: OOM (rollout-correlated), crash loops, image pull, missing Secret/ConfigMap, unschedulable, probes, nodes.
- Security triage: Falco + Trivy + RBAC + NetworkPolicy correlation with explained scoring; allowlist; platform namespaces hidden by default.
- GitOps remediation: plan → diff → policy guard → approval → branch/PR. Never writes to the cluster.
- MCP server (stdio + Streamable HTTP), CLI, bundled demo (`kubepilot demo`), Falco webhook receiver.
- Validated end to end on a single-node k3s lab with Falco, Trivy Operator and Claude Code.
- Hardening: credential privilege warning, redacted captures, authenticated and size-limited ingest, repo git hooks never run.
