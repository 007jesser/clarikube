#!/usr/bin/env bash
# Benign attack simulation against shop/payment-api: triggers Falco default rules
# ("Terminal shell in container", "Read sensitive file untrusted"). No real malware.
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
POD=$(kubectl -n shop get pod -l app=payment-api -o jsonpath='{.items[0].metadata.name}')
echo ">> interactive shell + reading /etc/shadow in $POD"
kubectl -n shop exec -it "$POD" -- sh -c 'id; cat /etc/shadow >/dev/null; exit 0'
echo ">> done. Ask your MCP client: 'Anything suspicious in the cluster in the last hour?'"
