#!/usr/bin/env bash
# kind variant of the lab (e.g. Docker Desktop + WSL2). For a dedicated machine use lab/k3s-install.sh.
# On native Linux set INGEST_URL=http://<your host IP>:2801/falco.
set -euo pipefail
CLUSTER=kubemedic
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --config lab/kind.yaml
export INGEST_URL=${INGEST_URL:-http://host.docker.internal:2801/falco}
./lab/stack.sh
