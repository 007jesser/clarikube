# Security model

## Threats considered
| Threat | Mitigation |
|---|---|
| **Prompt injection** via cluster content (event messages, Falco output, image names, annotations) | All cluster text passes `kubepilot.sanitize.clean`: invisible/bidi chars stripped, fake chat/tool markup removed, length-bounded, instruction-like text flagged `[kubepilot: possible prompt-injection text]`. Server instructions tell the model cluster text is data. Logs are not read in v1. |
| Agent tricked into changing the cluster | kubepilot has **no write path to the cluster**. Read-only ClusterRole, no Secrets/exec/logs. |
| Agent commits an unreviewed change | Commits go to a new branch only; merging is a human action in Git. Optional `KUBEPILOT_APPROVAL_MODE=cli` requires `kubepilot approve <id>` at a terminal. Dry-run by default. |
| Change makes security worse | Policy guard blocks plans that *introduce* privileged/host-namespace/hostPath/dangerous-caps/root/mutable-image violations. |
| Stale or tampered plan | Plans expire (30 min), are bound to repo HEAD and per-file SHA-256; approval token stored hashed, compared in constant time. |
| Path traversal | Names validated as RFC 1123; plan ids alphanumeric; commit refuses writes outside the worktree. |
| Spoofed Falco alerts | Ingest endpoint supports a bearer token, body size limit; NetworkPolicy admits only the `falco` namespace. |
| Exposed MCP endpoint | HTTP transport binds 127.0.0.1 by default; in-cluster it is reached only via port-forward. |

## Not covered (yet)
- Authentication on the Streamable HTTP MCP endpoint (put an authenticating proxy in front if exposed).
- A compromised host running the MCP server (it holds a kubeconfig and repo credentials).
- Supply-chain verification of the kubepilot image (sign with cosign before publishing).

Report vulnerabilities privately to the maintainer.
