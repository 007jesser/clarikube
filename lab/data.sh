#!/usr/bin/env bash
# Optional: adds a data tier (Redis, RabbitMQ, OpenSearch) and a dependent app to the lab, the GitOps way.
# Needs ~1.5 GB extra RAM and pulls ~1 GB of images (OpenSearch is the big one). SKIP_SEARCH=1 to leave it out.
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
LAB_REPO=${LAB_REPO:-$HOME/clarikube-lab-gitops}
[[ -d "$LAB_REPO/.git" ]] || { echo "run make lab-k3s (or lab-kind) first"; exit 1; }
mkdir -p "$LAB_REPO/data"
cp lab/gitops-data/*.yaml "$LAB_REPO/data/"
if [[ "${SKIP_SEARCH:-0}" == 1 ]]; then
  rm -f "$LAB_REPO/data/opensearch.yaml"
  sed -i '/opensearch.yaml/d' "$LAB_REPO/data/kustomization.yaml"
fi
git -C "$LAB_REPO" add -A data
git -C "$LAB_REPO" -c user.name=lab -c user.email=lab@local commit -qm "add data tier" || echo "(data tier already committed)"
kubectl apply -k "$LAB_REPO/data"
cat <<'MSG'

Data tier applied. Give it ~3 minutes (image pulls, OpenSearch OOM restarts), then:
  make lab-verify PHASE=data
Ask your MCP client: "What data systems run in the cluster and what is wrong with them?"
                     "Why does shop/reports keep crashing?"
Logs: set CLARIKUBE_READ_LOGS=true for clarikube to read failing containers' log signatures.
MSG
