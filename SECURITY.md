# Security model

## Threats considered
| Threat | Mitigation |
|---|---|
| **Prompt injection** via cluster content (event messages, Falco output, image names, annotations) | All cluster text passes `kubemedic.sanitize.clean`: invisible/bidi chars stripped, fake chat/tool markup removed, length-bounded, instruction-like text flagged `[kubemedic: possible prompt-injection text]`. Server instructions tell the model cluster text is data. Logs are opt-in (`KUBEMEDIC_READ_LOGS`): only failing containers, last 200 lines, and only a recognised error signature plus one sanitized line is ever returned. |
| Agent tricked into changing the cluster | kubemedic has **no write path to the cluster**. Read-only ClusterRole, no Secrets or exec; `pods/log` only in a separate optional ClusterRole. |
| Agent commits an unreviewed change | Commits go to a new branch only; merging is a human action in Git. Optional `KUBEMEDIC_APPROVAL_MODE=cli` requires `kubemedic approve <id>` at a terminal. Dry-run by default. |
| Change makes security worse | Policy guard blocks plans that *introduce* privileged/host-namespace/hostPath/dangerous-caps/root/mutable-image violations. |
| Stale or tampered plan | Plans expire (30 min), are bound to repo HEAD and per-file SHA-256; approval token stored hashed, compared in constant time. |
| Path traversal | Names validated as RFC 1123; plan ids alphanumeric; commit refuses writes outside the worktree. |
| Spoofed or flooding Falco alerts | Ingest **requires** a bearer token (constant-time compare) unless explicitly disabled for labs; 256 KB body cap enforced on Content-Length and while streaming; NetworkPolicy admits only the `falco` namespace in-cluster. |
| Exposed MCP endpoint | HTTP transport binds 127.0.0.1 by default with the MCP SDK's DNS-rebinding protection; in-cluster it is reached only via port-forward. |
| Over-privileged credentials | kubemedic only reads, but locally it uses whatever kubeconfig it is given. On start it runs SelfSubjectAccessReviews and surfaces a warning if it can read Secrets, create pods, exec or delete workloads. |
| Secrets in env vars and ConfigMaps | Env values and platform ConfigMaps (Fluent Bit, ingress-nginx; fetched by name with an optional role) are parsed in memory to find dependencies (e.g. `REDIS_URL`) but never returned; only names (env var, option, Service) appear in output. `kubemedic capture` redacts env values. |
| Malicious hooks in the GitOps repo | kubemedic runs git with `core.hooksPath=/dev/null` and `--no-verify`, so no repo hook executes during planning or commit. |
| Leaking data via bug reports | `kubemedic capture` never reads Secrets and redacts env values, secret-looking args/annotations, `last-applied-configuration` and managedFields. |

## Supply chain
- Dependencies are locked in `uv.lock`; CI installs with `--locked`. `pip-audit` reported no known vulnerabilities at release time.
- Sign release images (cosign) and enable GitHub's Dependabot/secret scanning on the public repository.

## Not covered (yet)
- Authentication on the Streamable HTTP MCP endpoint (put an authenticating proxy in front if exposed).
- A compromised host running the MCP server (it holds a kubeconfig and repo credentials).

Report vulnerabilities privately through GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab).
