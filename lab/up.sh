#!/usr/bin/env bash
# Local lab: kind + Falco (modern eBPF) + Falcosidekick -> kubepilot ingest on the host + Trivy Operator.
# Tested design for WSL2 + Docker Desktop; on native Linux replace host.docker.internal with your host IP.
# Requires: kind, kubectl, helm. Chart values are the documented ones; check `helm show values` if a chart changed.
set -euo pipefail

CLUSTER=kubepilot
INGEST_URL=${INGEST_URL:-http://host.docker.internal:2801/falco}
INGEST_TOKEN=${KUBEPILOT_INGEST_TOKEN:-change-me-$(date +%s)}

kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --config lab/kind.yaml

helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo add aqua https://aquasecurity.github.io/helm-charts/ >/dev/null
helm repo update >/dev/null

echo ">> Falco + Falcosidekick (webhook -> $INGEST_URL)"
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.webhook.address="$INGEST_URL" \
  --set-string falcosidekick.config.webhook.customheaders="Authorization:Bearer $INGEST_TOKEN"

echo ">> Trivy Operator"
helm upgrade --install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace \
  --set trivy.ignoreUnfixed=false

echo ">> demo workloads"
kubectl apply -f lab/workloads.yaml

cat <<EOF

Lab is coming up (Falco and Trivy take a few minutes on first start).

1) In another terminal, start the alert receiver on the host:
     KUBEPILOT_INGEST_TOKEN=$INGEST_TOKEN KUBEPILOT_ALERTS_DB=\$HOME/.local/state/kubepilot/alerts.db make ingest
2) Simulate an attack:   ./lab/attack.sh
3) Point your MCP client at:  kubepilot serve   with
     KUBEPILOT_ALERTS_DB=\$HOME/.local/state/kubepilot/alerts.db KUBEPILOT_ALLOWLIST=examples/allowlist.yaml
EOF
