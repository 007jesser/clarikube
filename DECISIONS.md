# Decisions

| # | Decision | Why |
|---|---|---|
| 1 | Fixes are delivered as Git commits on a branch (PR), never applied to the cluster | GitOps gives review, audit and rollback (`git revert`) for free, and keeps kubepilot's RBAC read-only. |
| 2 | Deterministic engines; the model only explains | Works with small local models, results are reproducible and testable, and scoring is auditable. |
| 3 | Same raw-dict normalization for live and fixture sources | One parser, fully covered by fixture tests; `kubepilot capture` turns any cluster into a test case. |
| 4 | Engines take `snap.now` instead of reading the clock | Deterministic tests and replay of captured incidents. |
| 5 | Default remediation = one concern per plan (reliability first, else security) | Small, reviewable PRs. `rollback-template` and `isolate-workload` are opt-in because they're disruptive. |
| 6 | Policy guard blocks only *introduced* deny violations | Lets kubepilot fix one issue in legacy manifests without being blocked by unrelated debt, while guaranteeing it never makes things worse. |
| 7 | Commits are made in a temporary `git worktree` | The user's checkout and branch are never touched. |
| 8 | Dry-run is the default (`KUBEPILOT_DRY_RUN=true`) | Safe first run. |
| 9 | Approval token returned with the plan, plus optional `cli` approval mode | Token alone can be replayed by the agent, so the tool descriptions demand human approval; `cli` mode adds a real out-of-band human gate. The PR review is the final gate either way. |
| 10 | No Secrets, logs or exec in v1 | Keeps the ClusterRole minimal; logs are the main prompt-injection vector and are deferred until the sanitizer has been battle-tested. |
| 11 | ruamel.yaml round-trip editing with indentation-style detection | Diffs show only the real change; comments are preserved. |
| 12 | Helm-templated files are skipped | They aren't valid YAML. Editing Helm values files is on the roadmap. |
| 13 | SQLite for Falco alerts, single replica | Simple and sufficient for v1; swap for a real store when multi-replica is needed. |
| 14 | `harden-security-context` does not set `readOnlyRootFilesystem` | It frequently breaks apps that write to /tmp; flagged as a reviewer note instead. |
| 15 | MCP Python SDK v2 (`MCPServer`) | Current major version; v1 `FastMCP` API is renamed. |
