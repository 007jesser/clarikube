#!/usr/bin/env bash
# Single-machine lab: k3s (one node) + Falco + Trivy Operator + kubepilot test workloads.
# Target: Ubuntu 22.04/24.04 (VM or bare metal), 4+ vCPU, 8 GB RAM recommended (4 GB works with LOW_MEM=1).
# Run from the repo root as a normal user with sudo:   ./lab/k3s-install.sh
set -euo pipefail

say() { printf '\n\033[1;36m>> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

# ------------------------------------------------------------ preflight
say "Preflight checks"
[[ -f lab/gitops/kustomization.yaml ]] || { echo "run from the kubepilot repo root"; exit 1; }
MEM_GB=$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)
KERNEL=$(uname -r)
echo "RAM: ${MEM_GB} GB | kernel: ${KERNEL} | CPUs: $(nproc)"
if (( MEM_GB < 6 )); then
  warn "Less than 6 GB RAM: enabling LOW_MEM mode (one Trivy scan at a time, tighter limits)."
  export LOW_MEM=1
fi
# Falco's modern eBPF probe needs kernel >= 5.8 with BTF.
if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
  warn "No /sys/kernel/btf/vmlinux: modern_ebpf will fail. Use Ubuntu 22.04+ (kernel 5.15+), or set FALCO_DRIVER=kmod."
fi
for bin in curl git; do command -v "$bin" >/dev/null || sudo apt-get install -y "$bin"; done

# ------------------------------------------------------------ k3s
if ! command -v k3s >/dev/null; then
  say "Installing k3s (single node, Traefik disabled)"
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik --write-kubeconfig-mode 600" sh -
fi
mkdir -p "$HOME/.kube"
sudo cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"
export KUBECONFIG="$HOME/.kube/config"
command -v kubectl >/dev/null || sudo ln -sf "$(command -v k3s)" /usr/local/bin/kubectl

say "Waiting for the node to be Ready"
kubectl wait --for=condition=Ready node --all --timeout=180s

# Falco looks for containerd at /run/containerd/containerd.sock to enrich alerts with pod names.
# k3s runs its own containerd elsewhere, so link it (persisted across reboots via tmpfiles.d).
say "Linking k3s containerd socket for Falco pod metadata"
echo "L+ /run/containerd/containerd.sock - - - - /run/k3s/containerd/containerd.sock" \
  | sudo tee /etc/tmpfiles.d/k3s-containerd-falco.conf >/dev/null
sudo systemd-tmpfiles --create /etc/tmpfiles.d/k3s-containerd-falco.conf

# ------------------------------------------------------------ tools
if ! command -v helm >/dev/null; then
  say "Installing Helm"
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi
if ! command -v uv >/dev/null; then
  say "Installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
uv sync

# ------------------------------------------------------------ stack
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
export INGEST_URL="http://${NODE_IP}:2801/falco"
./lab/stack.sh

if command -v ufw >/dev/null && sudo ufw status | grep -q "Status: active"; then
  warn "ufw is active: allow pods to reach the ingest port:  sudo ufw allow from 10.42.0.0/16 to any port 2801"
fi
