# Security scoring

Every point is attributable to a concrete signal, shown in the incident's `signals` list.
Source of truth: `SCORING` in `src/kubepilot/engine/security.py`.

| Signal | Points |
|---|---|
| Falco alert, highest priority in window: Critical/Alert/Emergency | 40 |
| — Error | 30 |
| — Warning | 20 |
| — Notice | 10 |
| Each additional distinct Falco rule (cap +15) | +5 |
| ≥1 **critical** CVE in a running image (Trivy) | 25 |
| ≥1 high CVE (no criticals) | 10 |
| Privileged container | 20 |
| hostNetwork / hostPID / hostIPC | 15 |
| hostPath volume | 15 |
| Dangerous capability added (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, …) | 10 |
| May run as root (no runAsNonRoot / runAsUser ≠ 0) | 10 |
| allowPrivilegeEscalation not false | 5 |
| No NetworkPolicy restricts ingress | 10 |
| Selected by a LoadBalancer / NodePort Service (reachable from outside the cluster) | 15 |
| ServiceAccount risky RBAC (sum, cap 30): cluster-admin 30 (20 namespaced), read all secrets 20 cluster / 15 namespaced, rbac escalate/bind/impersonate 20, nodes/proxy 20, pods/exec 10, create workloads 10 | ≤30 |

**Correlation:** if a runtime alert of Warning or higher co-occurs with a critical CVE *or* excessive
exposure, the sum is multiplied by **1.5** (an active process on an exploitable / over-privileged
workload is far more likely to be a real compromise). Scores cap at 100.

RBAC only counts when the ServiceAccount token is automounted.

| Score | Severity |
|---|---|
| ≥ 70 | critical |
| ≥ 45 | high |
| ≥ 25 | medium |
| ≥ 10 | low |

Allowlisted alerts (`KUBEPILOT_ALLOWLIST`) are excluded from scoring and counted in `suppressed_alerts`.
