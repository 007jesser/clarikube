# Contributing

Thanks for helping. clarikube is alpha, so issues describing real clusters it misdiagnosed are the most valuable contribution.

## Dev setup
```bash
uv sync
make check            # ruff + mypy --strict + pytest (no cluster needed)
uv run clarikube demo
```

## Ground rules (see CLAUDE.md for the full list)
- **Read-only toward the cluster.** No code path may create, patch or delete cluster objects. Fixes are Git changes.
- **Deterministic engines.** Diagnosis and scoring live in `src/clarikube/engine/`, are pure functions over a snapshot, and every rule has a test.
- **Untrusted input.** Anything from the cluster goes through `clarikube.sanitize` before it reaches a model.
- New diagnosis rule? Add a fixture scenario under `src/clarikube/demo/cluster/` or a capture, plus a test.

## Reporting a misdiagnosis
Run `clarikube capture --out ./capture -n <namespace>`. It redacts env values, `last-applied-configuration` and
managedFields, but **review the files before attaching them**: names, images and labels remain.

## Security issues
Please don't open public issues for vulnerabilities; see SECURITY.md.
