#!/usr/bin/env bash
# Starts the kubepilot MCP server over stdio, wired to the lab. Prints nothing on stdout except MCP traffic,
# so it is safe to launch remotely:  ssh user@lab-machine ~/kubepilot/lab/mcp.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
STATE=${KUBEPILOT_STATE_DIR:-$HOME/.local/state/kubepilot}
mkdir -p "$STATE"
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
export KUBEPILOT_STATE_DIR="$STATE"
export KUBEPILOT_ALERTS_DB="$STATE/alerts.db"
export KUBEPILOT_ALLOWLIST="$PWD/lab/allowlist.yaml"
export KUBEPILOT_GITOPS_REPO=${KUBEPILOT_GITOPS_REPO:-$HOME/kubepilot-lab-gitops}
export KUBEPILOT_DRY_RUN=${KUBEPILOT_DRY_RUN:-false}
export KUBEPILOT_READ_LOGS=${KUBEPILOT_READ_LOGS:-true}   # your own lab: read failing containers' log signatures
exec uv run --quiet kubepilot serve 2>>"$STATE/mcp.log"
