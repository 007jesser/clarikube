#!/usr/bin/env bash
# Run kubemedic the way the README recommends: with the read-only identity from deploy/rbac.yaml instead of
# your admin kubeconfig. Creates the ServiceAccount + roles, a short-lived token, and a kubeconfig that uses it,
# then proves what that identity can and cannot do and produces a launch report with it.
#   make lab-readonly
set -euo pipefail
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
OUT=${OUT:-$HOME/.kube/kubemedic-readonly.yaml}
say() { printf '\n\033[1;36m>> %s\033[0m\n' "$*"; }

say "Applying deploy/rbac.yaml (read-only ClusterRole + optional logs/config roles)"
kubectl apply -f deploy/rbac.yaml >/dev/null

say "Building $OUT with a 2h token for ServiceAccount kubemedic/kubemedic"
TOKEN=$(kubectl create token kubemedic -n kubemedic --duration=2h)
SERVER=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
umask 077
cat > "$OUT" <<KCFG
apiVersion: v1
kind: Config
clusters: [{name: lab, cluster: {server: "$SERVER", certificate-authority-data: "$CA"}}]
users: [{name: kubemedic-readonly, user: {token: "$TOKEN"}}]
contexts: [{name: kubemedic-readonly, context: {cluster: lab, user: kubemedic-readonly}}]
current-context: kubemedic-readonly
KCFG

say "What the identity can do (expected: yes yes yes / no no no no no)"
for check in "list pods -A" "get pods/log -n shop" "list ingresses -A" \
             "get secrets -n shop" "create pods -n shop" "delete deployments -n shop" \
             "create pods/exec -n shop" "patch deployments -n shop"; do
  # shellcheck disable=SC2086
  printf '  %-30s %s\n' "$check" "$(KUBECONFIG=$OUT kubectl auth can-i $check 2>/dev/null || true)"
done

say "Launch report with the read-only identity (no privilege warning expected)"
KUBECONFIG=$OUT make --no-print-directory lab-report
echo
echo "To use it with Claude Code:  claude mcp add --scope user kubemedic-ro -e KUBECONFIG=$OUT -- $PWD/lab/mcp.sh"
