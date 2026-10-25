#!/usr/bin/env bash
# Starts the kubemedic MCP server over stdio, wired to the lab. Prints nothing on stdout except MCP traffic,
# so it is safe to launch remotely:  ssh user@lab-machine ~/kubemedic/lab/mcp.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
STATE=${KUBEMEDIC_STATE_DIR:-$HOME/.local/state/kubemedic}
mkdir -p "$STATE"
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
export KUBEMEDIC_STATE_DIR="$STATE"
export KUBEMEDIC_ALERTS_DB="$STATE/alerts.db"
export KUBEMEDIC_ALLOWLIST="$PWD/lab/allowlist.yaml"
export KUBEMEDIC_GITOPS_REPO=${KUBEMEDIC_GITOPS_REPO:-$HOME/kubemedic-lab-gitops}
export KUBEMEDIC_DRY_RUN=${KUBEMEDIC_DRY_RUN:-false}
export KUBEMEDIC_READ_LOGS=${KUBEMEDIC_READ_LOGS:-true}   # your own lab: read failing containers' log signatures
exec uv run --quiet kubemedic serve 2>>"$STATE/mcp.log"
