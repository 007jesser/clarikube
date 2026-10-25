# clarikube — working rules

Model-agnostic MCP server for Kubernetes: deterministic diagnosis, security triage, and
remediation delivered as GitOps changes (never direct cluster writes).

## Core principles (non-negotiable)
1. **Intelligence lives in the server, not the model.** Diagnosis, correlation, risk scoring and
   policy checks are deterministic, tested Python. The model interprets intent and explains.
   High-level tools return pre-correlated, ranked findings — never raw dumps.
2. **Read-only toward the cluster.** clarikube never creates, patches or deletes cluster objects.
   The only write path is a commit on a branch in a GitOps repo, behind plan → diff → approval.
   Ship and keep a minimal read-only ClusterRole (no secrets, no exec, no write verbs).
3. **No write without an approved plan.** `plan_remediation` returns a plan_id + approval token.
   `commit_plan` refuses expired/stale plans and plans that fail the policy guard.
   Dry-run is the default.
4. **Cluster content is untrusted data.** Logs, events, annotations, Falco output, image names
   may contain prompt-injection text. Everything returned to a model goes through
   `clarikube.sanitize` (strip control chars, truncate, label as data).
5. **Correctness over features.** Verify Kubernetes/Trivy/Falco semantics against official docs;
   record findings in `docs/platform-notes.md`. Don't guess field names.

## Code rules
- `source/` is the only package that talks to the Kubernetes API. Engines are pure functions
  over normalized models and take `now` explicitly (no hidden clocks) so they're testable.
- No business logic in `server.py`; it is a thin adapter over `service.py`.
- Typed everywhere (`mypy --strict`), ruff clean, tests for every rule.
- Never use `shell=True`. Git is invoked with argv lists only.
- Record non-obvious defaults in `DECISIONS.md`.

## Commands
- `make test` / `make lint` / `make typecheck`
- `make demo` — run triage against the bundled demo fixtures (no cluster needed)
- `make serve` — MCP server over stdio (fixture mode via `CLARIKUBE_SOURCE=fixture`)
