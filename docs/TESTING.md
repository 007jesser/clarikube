# Testing kubepilot on a single machine

Goal: prove every kubepilot feature against a **real** cluster, with automated PASS/FAIL checks, in about an hour.

```
Phase 0  install        k3s + Falco + Trivy + lab workloads            make lab-k3s
Phase 1  baseline       missing secret, unschedulable, risky workload   make lab-verify PHASE=baseline
Phase 2  bad releases   OOM after rollout, bad image tag                make lab-break   → PHASE=broken
Phase 3  attack         shell + /etc/shadow read in payment-api         make lab-attack  → PHASE=attacked
Phase 4  fix via AI     Claude plans → you approve → branch → apply     make lab-fix     → PHASE=fixed
Phase 5  capture        save the real cluster as a regression fixture   make lab-capture
```

## 0. The machine

| Option | Specs | Notes |
|---|---|---|
| **Ubuntu VM on your laptop** (recommended) | 4 vCPU, 8 GB RAM, 40 GB disk | Hyper-V or VirtualBox, Ubuntu Server 24.04. Bridged/external network so the laptop can SSH in. |
| Spare PC | 4 GB RAM | Works in LOW_MEM mode (auto-detected), but Trivy scans are slow. Close everything else. |
| Bare-metal Ubuntu | 8 GB+ | Best performance. |

Requirements: Ubuntu 22.04 or 24.04 (kernel ≥ 5.8 with BTF; Falco's modern eBPF probe needs it), internet access, a user with sudo.

## 1. Install (≈10 min)

```bash
sudo apt-get update && sudo apt-get install -y git make unzip
# copy kubepilot.zip to the machine (scp, USB, ...) then:
unzip kubepilot.zip && cd kubepilot
make lab-k3s
```

What it does: installs k3s (single node, Traefik off), links k3s's containerd socket so Falco can name pods, installs Helm and uv, deploys Falco + Falcosidekick (alerts → `http://<node-ip>:2801/falco`, bearer token in `~/.local/state/kubepilot/ingest-token`), Trivy Operator, and the lab workloads from `lab/gitops/` (copied to the git repo `~/kubepilot-lab-gitops`).

Then open a **second terminal** and leave this running:

```bash
cd kubepilot && make lab-ingest
```

Wait until everything is up (Falco 1–3 min; Trivy scans every image once, 5–15 min):

```bash
kubectl get pods -A
kubectl get vulnerabilityreports -A      # wait for shop/payment-api entries
```

## 2. Phase 1: baseline

```bash
make lab-verify PHASE=baseline
```

Expected:

| Check | Expected |
|---|---|
| connected to a live cluster | PASS |
| api: missing Secret detected | PASS |
| worker: Pending/unschedulable, request larger than any node | PASS |
| payment-api: incident; secrets access, no NetworkPolicy, root | PASS |
| payment-api: CVEs from Trivy | PASS (WARN = Trivy still scanning, re-run later) |
| checkout, frontend healthy | PASS |

## 3. Phase 2: bad releases

```bash
make lab-break            # commits "release: cut checkout memory, bump frontend" and applies it
sleep 120
make lab-verify PHASE=broken
```

Expected: checkout **OOMKilled and correlated with the rollout** ("lowered the memory limit from 512Mi to 128Mi"), plus a memory fix proposed; frontend image pull failure, "tag does not exist", revert to `nginx:1.27` proposed.

## 4. Phase 3: attack

```bash
make lab-attack           # interactive shell + read /etc/shadow in payment-api (benign)
make lab-verify PHASE=attacked
```

Expected: Falco alerts mapped to `Deployment/shop/payment-api`; severity high/critical with the ×1.5 correlation; backup CronJob alerts **suppressed** by `lab/allowlist.yaml` (WARN until the CronJob has run once; it runs every 5 min).

## 5. Phase 4: let the AI fix it

### Connect an MCP client (recommended: Claude Code on the lab machine)

kubepilot is a local stdio MCP server, so the client must run where it can start it. Simplest and verified:

```bash
curl -fsSL https://claude.ai/install.sh | bash && source ~/.bashrc
claude mcp add --scope user kubepilot -- ~/kubepilot/lab/mcp.sh
claude mcp list            # kubepilot ... ✔ Connected
cd ~ && claude             # then /mcp should list 10 kubepilot tools
```

`--scope user` matters: without it the server is only registered for the folder you ran `claude mcp add` in.

**Alternative, Claude Desktop on another machine via SSH:** set up key-based SSH (no password prompt), then add to the
Desktop app's local MCP config (Settings → Developer → Edit Config):

```json
{ "mcpServers": { "kubepilot-lab": { "command": "ssh", "args": ["-T", "user@LAB_IP", "~/kubepilot/lab/mcp.sh"] } } }
```

Only clients that launch **local** MCP servers can use it; cloud-hosted chat sessions cannot reach your lab.
Server logs: `~/.local/state/kubepilot/mcp.log` on the lab machine.

### Script to follow in the chat

1. *"Triage the cluster."* It should list the 4 reliability issues plus payment-api as the top incident.
2. *"Why is checkout failing? Prepare a fix."* Expect a plan restoring `memory: 512Mi` with a one-line diff. Approve it in chat; it commits branch `kubepilot/checkout-…`. Plans expire after 30 minutes; if you approve later, kubepilot refuses and you simply ask for a new plan.
3. *"Fix frontend too."* Expect a plan reverting the image to `nginx:1.27`.
4. *"Treat payment-api as an incident."* Expect the containment plan (`isolate-workload`) plus the manual steps (rebuild image, reduce RBAC, rotate credentials).
5. Merge and apply each branch (this plays the role of Argo CD):

```bash
git -C ~/kubepilot-lab-gitops branch          # list kubepilot/* branches
make lab-fix BRANCH=kubepilot/checkout-<id>    # use the real names; run one at a time and type y
make lab-fix BRANCH=kubepilot/frontend-<id>
sleep 60 && make lab-verify PHASE=fixed
```

**Expected lesson:** if you merge the default *security hardening* plan for payment-api, the pod fails with `CreateContainerConfigError` because `nginx:1.19.0` runs as root and the plan set `runAsNonRoot: true`. kubepilot's reviewer note warns about exactly this. That's why fixes are PRs and not direct applies. Undo with `git revert` (the command is printed by `lab-fix`).

### Approval-mode test (optional)
Set `KUBEPILOT_APPROVAL_MODE=cli` in `lab/mcp.sh`; `commit_plan` should then refuse until you run `make lab-approve ID=<plan-id>` on the lab machine.

## 5b. Optional: data tier (Redis, RabbitMQ, OpenSearch)

Needs ~1.5 GB more RAM (`SKIP_SEARCH=1` leaves OpenSearch out).

```bash
make lab-data                 # commits lab/gitops-data into the lab repo and applies it
make lab-verify PHASE=data    # after ~3 minutes
```

In `lab/mcp.sh` set `KUBEPILOT_READ_LOGS=true` (your kubeconfig can read logs), then ask:
- "What data systems run in the cluster and what's wrong with them?"
- "Why does shop/reports keep crashing?" → should blame OpenSearch (heap = limit → OOMKilled).
- "Fix the Redis exposure" → `make-service-internal` diff on `data/redis.yaml`.
- After `make lab-fix BRANCH=...`: "Did plan <id> fix it?" → `verify_fix`.

## 6. Phase 5: capture

```bash
make lab-capture          # writes examples/lab-capture-<date>/ (no Secrets)
```

This snapshot is a real-cluster fixture: add it to the tests so real-world quirks can't regress. Send it back to me along with any FAILs.

## Reset / clean up

```bash
make lab-reset                                   # baseline workloads, new lab repo, plans cleared
/usr/local/bin/k3s-uninstall.sh                  # remove k3s completely
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Falco pod CrashLoop, "modern_ebpf" errors | Kernel lacks BTF. `FALCO_DRIVER=kmod ./lab/stack.sh` (needs kernel headers: `sudo apt install linux-headers-$(uname -r)`). |
| <a id="falco"></a>Alerts arrive but `PHASE=attacked` says not mapped to the workload | Alerts lack `k8s.pod.name`, so Falco can't see containerd. Check `ls -l /run/containerd/containerd.sock` → must point to `/run/k3s/containerd/containerd.sock`; then `kubectl -n falco rollout restart ds/falco`. Check `kubectl -n falco logs ds/falco` for container-engine errors. |
| `lab-ingest` logs `401 Unauthorized` | Falcosidekick isn't sending the token. Check `kubectl -n falco get secret falco-falcosidekick -o go-template='{{.data.WEBHOOK_CUSTOMHEADERS \| base64decode}}'` shows `Authorization:Bearer ...`; the chart key is `webhook.customHeaders` (camelCase). Keep `make lab-ingest` running: alerts sent while it is stopped are lost. |
| No alerts at all in `lab-ingest` | `kubectl -n falco logs deploy/falco-falcosidekick` shows webhook errors? Check the URL/IP, `sudo ufw allow from 10.42.0.0/16 to any port 2801`, and that `make lab-ingest` runs. Test: `curl -XPOST -H "Authorization: Bearer $(cat ~/.local/state/kubepilot/ingest-token)" -d '{"rule":"test","priority":"Notice","output_fields":{"k8s.ns.name":"shop","k8s.pod.name":"x"}}' http://<node-ip>:2801/falco` |
| "Terminal shell in container" missing | Run `lab/attack.sh` from a real terminal (needs `-t`). Falco rule names/priorities change between releases; check `kubectl -n falco logs ds/falco`. |
| Trivy scan pods stuck in `Init:0/1` and keep restarting | Each job downloads the vulnerability DB and times out. `lab/stack.sh` enables the built-in Trivy server (one download); on an existing install: `helm upgrade trivy-operator aqua/trivy-operator -n trivy-system --reuse-values --set operator.builtInTrivyServer=true --set operator.scanJobTimeout=15m --set operator.scanJobsConcurrentLimit=3` |
| `CVEs from Trivy` stays WARN | `kubectl -n trivy-system logs deploy/trivy-operator`; scans need internet to pull the vulnerability DB. LOW_MEM mode scans one image at a time. |
| `checkout` OOM not correlated with rollout | `kubectl -n shop get rs` must show two checkout ReplicaSets (revision 1 and 2). If you re-applied the baseline, run `make lab-reset` then `make lab-break` again. |
| Claude Desktop can't start the server | Run `ssh -T user@LAB_IP ~/kubepilot/lab/mcp.sh` manually: it must wait silently (no password prompt, no output). Check `~/.local/state/kubepilot/mcp.log`. |
| A Helm `--set` value is rejected | Charts evolve; compare with `helm show values falcosecurity/falco` / `aqua/trivy-operator` and adjust `lab/stack.sh`. |

## What to send back
1. Output of each `make lab-verify` phase (copy/paste).
2. Any FAIL detail and the matching `kubectl` output.
3. The `examples/lab-capture-*` folder.
4. Notes on the Claude conversation: anything it misunderstood or any tool it misused.
