#!/usr/bin/env bash
# Back to a clean baseline: recreate the lab GitOps repo, re-apply workloads, clear kubepilot plans.
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
LAB_REPO=${LAB_REPO:-$HOME/kubepilot-lab-gitops}
STATE=${KUBEPILOT_STATE_DIR:-$HOME/.local/state/kubepilot}
[[ -f "$LAB_REPO/data/kustomization.yaml" ]] && { kubectl delete -k "$LAB_REPO/data" --ignore-not-found --wait=true || true; }
kubectl delete -k "$LAB_REPO" --ignore-not-found --wait=true || true
kubectl delete networkpolicy -n shop -l app.kubernetes.io/managed-by=kubepilot --ignore-not-found
rm -rf "$LAB_REPO" "$STATE/plans" "$STATE/approvals" "$STATE/audit.jsonl"
mkdir -p "$LAB_REPO"
cp lab/gitops/*.yaml "$LAB_REPO/"
git -C "$LAB_REPO" init -q -b main
git -C "$LAB_REPO" add -A
git -C "$LAB_REPO" -c user.name=lab -c user.email=lab@local commit -qm "baseline workloads"
kubectl apply -k "$LAB_REPO"
echo "Reset done (Falco alert history kept in $STATE/alerts.db)."
