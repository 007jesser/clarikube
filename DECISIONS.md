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
| 10 | No Secrets or exec; logs opt-in (see 23) | Keeps the default ClusterRole minimal. |
| 11 | ruamel.yaml round-trip editing with indentation-style detection | Diffs show only the real change; comments are preserved. |
| 12 | Helm chart templates are never edited; values are (see 24) | Templates aren't valid YAML and are owned by the chart author. |
| 13 | SQLite for Falco alerts, single replica | Simple and sufficient for v1; swap for a real store when multi-replica is needed. |
| 14 | `harden-security-context` does not set `readOnlyRootFilesystem` | It frequently breaks apps that write to /tmp; flagged as a reviewer note instead. |
| 15 | MCP Python SDK v2 (`MCPServer`) | Current major version; v1 `FastMCP` API is renamed. |
| 16 | Demo data ships inside the package (`kubepilot/demo`) | `uvx kubepilot demo` must work without cloning; found by testing the built wheel. |
| 17 | Platform namespaces hidden from cluster-wide security views by default | Real-cluster test: Falco/Trivy are privileged by design and drowned out application risk. Explicit namespace or `include_system` shows them. |
| 18 | Ingest refuses to start without a token | Unauthenticated alert injection would let anyone fake or bury incidents. Opt-out env var for throwaway labs only. |
| 19 | Git hooks disabled for kubepilot's git calls | A planning tool must not execute arbitrary repo code. |
| 20 | SelfSubjectAccessReview at startup | Users run it with admin kubeconfigs; warn instead of silently holding write power. |
| 21 | Components detected from operator CRs first, then Helm/StatefulSet images | The operator's CR is the source of truth and the right place to fix things; image matching covers Helm and hand-written manifests. Exporters/UIs/operators themselves are excluded by name. |
| 22 | Dependencies inferred from env values, but values never leave the process | Env is the only universal wiring signal without a service mesh; values routinely embed credentials, so output carries only env var name + Service name. Plain words count as hosts only when the env var name looks like an address (`*_HOST`, `*_URL`, …). |
| 23 | Logs are opt-in, failing containers only, ≤200 lines/64 KiB, signatures only | Logs are the largest prompt-injection surface. Returning a known signature plus one sanitized line gives the model the cause without giving attackers a channel. |
| 24 | Helm values edited only where the current value equals the live value | Value paths differ per chart; matching on the live value avoids guessing and refuses on zero or several matches. |
| 25 | Component findings' hints win over generic ones in a plan | The Kafka/JVM-aware fix (CR edit, heap-aware limit) is more correct than the generic container fix for the same symptom. |
| 26 | `plan_revert` produces a normal plan, never a direct revert | Undo goes through the same diff, approval and audit as the original change. |
| 27 | `verify_fix` compares file contents when the commit is not an ancestor | Squash and rebase merges rewrite commits; content equality is the reliable signal. Uses local refs only (no network fetch). |
| 28 | Component analysis always uses a cluster-wide snapshot | Apps and their data systems usually live in different namespaces; a namespace-scoped view would miss the root cause. |
| 29 | `kubepilot ask` uses the in-process MCP server and hides `commit_plan` | Same tool schemas as any MCP client; a local model can plan but never commit. Zero extra dependencies (urllib). |
| 30 | `kubepilot commit` requires an interactive TTY | Gives users without an MCP client a commit path while keeping agents (which run shells without a TTY) out of it. |
| 31 | Operator CRD versions are tried newest-first | Strimzi 1.0 removed `v1beta2`; older clusters only serve it. One code path supports both. |
| 32 | Proposed memory limits are rounded up (128Mi / 512Mi steps) | `2731Mi` reads like a bug in a PR; humans write `3Gi`. |
| 33 | Platform layers reuse the component engine (`layer`: data / edge / logging) | One detection, dependency and remediation path for every layer; adding a system is checks + image patterns, not a new subsystem. |
| 34 | ConfigMaps are fetched by name, only for platform pods, behind an optional role | Fluent Bit and ingress-nginx are configured by ConfigMaps; listing all ConfigMaps cluster-wide would read far more than needed. Contents never leave the process. |
| 35 | Opinionated-but-common gaps are low/medium, never critical | e.g. "no WAF" is not flagged at all; DetectionOnly WAF is medium; local rate limits are low. Critical is reserved for exploitable or outage-level issues (exposed Kong admin, IngressNightmare, expired cert). |
| 36 | One file is opened once per plan (`_Workspace`) | Two fixes in the same multi-document file (DaemonSet + its ConfigMap) previously produced two conflicting changes; now they merge into one diff. Found while building the Fluent Bit fixes. |
| 37 | A hint kind can carry several independent edits (`set-fluentbit-option:Retry_Limit`, `:Mem_Buf_Limit`) | Selecting the kind applies all of them; an exact key applies one. |
| 38 | Platform tools are a catalog (image → kind → layer → impact sentence) | Adding a tool is one table row plus optional checks; "down" findings say what breaks for users (DNS, sync, scaling…) instead of a generic "pod not ready". |
| 39 | Status-driven checks read the tools' own status (conditions, phases), not their logs or APIs | Operators already summarise their health in status; reading it needs only `get/list` and no network access to the tool. |
| 40 | Prometheus alerts arrive by Alertmanager webhook, not by querying Prometheus | Querying would need `services/proxy` (reaches any Service) or network access; a webhook into the existing authenticated ingest keeps kubepilot read-only and least-privileged. |
| 41 | API discovery before listing operator CRs | Most clusters run a few of ~45 supported resource types; discovery (cached 5 min) avoids dozens of 404 requests per snapshot. |
| 42 | Controllers without pods are workloads too | A Deployment whose pods are all denied by admission has zero pods; it must still be diagnosable. |
| 43 | Cross-layer root causes are explicit findings ("Likely root cause: ExternalSecret … is failing to sync") | The model should not have to infer the link; the evidence (missing Secret name ↔ ExternalSecret target) is computed. |
