#!/usr/bin/env bash
# Simulates two bad releases the GitOps way (commit + apply), so kubepilot can correlate failures with
# the rollout that caused them:
#   checkout: memory limit 512Mi -> 128Mi   (app needs ~200MB  => OOMKilled)
#   frontend: nginx:1.27 -> nginx:1.27.99-typo  (tag does not exist => ImagePullBackOff)
set -euo pipefail
LAB_REPO=${LAB_REPO:-$HOME/kubepilot-lab-gitops}
cd "$LAB_REPO"
sed -i 's/memory: 512Mi/memory: 128Mi/' checkout.yaml
sed -i 's#image: nginx:1.27$#image: nginx:1.27.99-typo#' frontend.yaml
git -c user.name=lab -c user.email=lab@local commit -qam "release: cut checkout memory, bump frontend"
kubectl apply -k .
echo "Broken releases applied. Wait ~2 minutes for OOM restarts and pull back-offs, then:"
echo "  make lab-verify PHASE=broken"
