#!/usr/bin/env bash
# Plays the role of Argo CD / Flux after a human merges a kubepilot PR:
# merges the kubepilot branch into main in the lab GitOps repo and applies it.
#   ./lab/apply-fix.sh kubepilot/checkout-<planid>
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
BRANCH=${1:?usage: apply-fix.sh <kubepilot branch>   (see: git -C ~/kubepilot-lab-gitops branch)}
LAB_REPO=${LAB_REPO:-$HOME/kubepilot-lab-gitops}
git -C "$LAB_REPO" log --oneline -1 "$BRANCH"
git -C "$LAB_REPO" diff --stat main "$BRANCH"
read -r -p "Merge $BRANCH into main and apply to the cluster? [y/N] " ok
[[ "$ok" =~ ^[Yy]$ ]] || { echo "aborted"; exit 1; }
git -C "$LAB_REPO" -c user.name=lab -c user.email=lab@local merge --no-ff -q -m "Merge $BRANCH" "$BRANCH"
kubectl apply -k "$LAB_REPO"
echo "Applied. Watch: kubectl -n shop get pods -w    Undo: git -C $LAB_REPO revert -m 1 HEAD && kubectl apply -k $LAB_REPO"
