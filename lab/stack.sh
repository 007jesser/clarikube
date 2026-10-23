#!/usr/bin/env bash
# Installs Falco + Falcosidekick, Trivy Operator and the lab workloads into the current kube-context.
# Shared by k3s-install.sh (single machine) and up.sh (kind). Idempotent: safe to re-run.
#   INGEST_URL   where Falcosidekick posts alerts (kubepilot ingest), required
#   LOW_MEM=1    tighter resources for 4 GB machines
#   FALCO_DRIVER modern_ebpf (default) | kmod | ebpf
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
: "${INGEST_URL:?set INGEST_URL, e.g. http://<host-ip>:2801/falco}"
LAB_REPO=${LAB_REPO:-$HOME/kubepilot-lab-gitops}
STATE=${KUBEPILOT_STATE_DIR:-$HOME/.local/state/kubepilot}
mkdir -p "$STATE"
TOKEN_FILE="$STATE/ingest-token"
[[ -s "$TOKEN_FILE" ]] || { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"; }
TOKEN=$(cat "$TOKEN_FILE")

say() { printf '\n\033[1;36m>> %s\033[0m\n' "$*"; }

helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo add aqua https://aquasecurity.github.io/helm-charts/ >/dev/null 2>&1 || true
helm repo update >/dev/null

say "Falco (${FALCO_DRIVER:-modern_ebpf}) + Falcosidekick -> $INGEST_URL"
FALCO_ARGS=(
  --set driver.kind="${FALCO_DRIVER:-modern_ebpf}"
  --set tty=true
  --set falcosidekick.enabled=true
  --set falcosidekick.config.webhook.address="$INGEST_URL"
  --set-string falcosidekick.config.webhook.customHeaders="Authorization:Bearer $TOKEN"
)
if [[ "${LOW_MEM:-0}" == 1 ]]; then
  FALCO_ARGS+=(--set resources.requests.memory=256Mi --set resources.limits.memory=512Mi
               --set falcosidekick.replicaCount=1)
fi
helm upgrade --install falco falcosecurity/falco -n falco --create-namespace "${FALCO_ARGS[@]}"

say "Trivy Operator"
TRIVY_ARGS=(--set trivy.ignoreUnfixed=false)
if [[ "${LOW_MEM:-0}" == 1 ]]; then
  TRIVY_ARGS+=(--set operator.scanJobsConcurrentLimit=1)
fi
helm upgrade --install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace "${TRIVY_ARGS[@]}"

say "Lab GitOps repo at $LAB_REPO"
if [[ ! -d "$LAB_REPO/.git" ]]; then
  mkdir -p "$LAB_REPO"
  cp lab/gitops/*.yaml "$LAB_REPO/"
  git -C "$LAB_REPO" init -q -b main
  git -C "$LAB_REPO" add -A
  git -C "$LAB_REPO" -c user.name=lab -c user.email=lab@local commit -qm "baseline workloads"
fi
kubectl apply -k "$LAB_REPO"

cat <<EOF

Done. Falco and Trivy need a few minutes on first start (Trivy scans every image once).

Next (see docs/TESTING.md):
  terminal 1:  make lab-ingest           # receives Falco alerts
  terminal 2:  make lab-verify PHASE=baseline
EOF
