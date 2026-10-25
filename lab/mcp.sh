#!/usr/bin/env bash
# Starts the clarikube MCP server over stdio, wired to the lab. Prints nothing on stdout except MCP traffic,
# so it is safe to launch remotely:  ssh user@lab-machine ~/clarikube/lab/mcp.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
STATE=${CLARIKUBE_STATE_DIR:-$HOME/.local/state/clarikube}
mkdir -p "$STATE"
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
export CLARIKUBE_STATE_DIR="$STATE"
export CLARIKUBE_ALERTS_DB="$STATE/alerts.db"
export CLARIKUBE_ALLOWLIST="$PWD/lab/allowlist.yaml"
export CLARIKUBE_GITOPS_REPO=${CLARIKUBE_GITOPS_REPO:-$HOME/clarikube-lab-gitops}
export CLARIKUBE_DRY_RUN=${CLARIKUBE_DRY_RUN:-false}
export CLARIKUBE_READ_LOGS=${CLARIKUBE_READ_LOGS:-true}   # your own lab: read failing containers' log signatures
exec uv run --quiet clarikube serve 2>>"$STATE/mcp.log"
