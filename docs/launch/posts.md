# Launch posts (drafts)

Replace NAME / links once the project name and repo are final. Numbers come from
docs/benchmarks/k3s-lab-2026-10.md; don't round them up.

---

## Show HN

**Title:** Show HN: NAME – AI that finds the real root cause in Kubernetes and fixes it as a Git PR

**Body:**

I'm a DevOps engineer. Every "AI for Kubernetes" tool I tried either dumps kubectl output into a model and
hopes, or gives the agent cluster-admin and lets it run commands. Neither is something I'd let near production.

NAME is an MCP server (works with Claude, Cursor, any MCP client, or a local model via Ollama) that does the
analysis itself, in deterministic, tested code, and hands the model short, correlated findings:

- It follows failures across layers: "orders is crashing" → "Kafka has 2/3 brokers and min.insync = RF" →
  "broker 2's StorageClass was deleted". It knows Kafka, RabbitMQ, OpenSearch, Redis, Postgres, ingress-nginx,
  Kong, Fluent Bit, Argo CD/Flux, External Secrets, HPA/Karpenter, Velero and more.
- It never writes to the cluster. Fixes are a diff in your GitOps repo, policy-checked, committed to a branch
  after you approve; `verify_fix` checks it worked, `plan_revert` undoes it.
- Read-only RBAC, no Secrets, env values never sent to the model, log lines sanitized against prompt injection.

On my k3s lab (5 broken apps + a misconfigured data tier) Claude found all 5 root causes in 33 s using ~9.8k
tokens — the raw kubectl equivalent is ~67k tokens. The first run on a real cluster also found 4 bugs in my
own code that the synthetic demo missed; they're now regression tests (details in the repo).

Try it without a cluster: `uvx NAME demo`.

Alpha, Apache-2.0. I'd love to hear what breaks on your clusters, and what you'd never let an AI do.

---

## r/kubernetes

**Title:** I built an MCP server that traces K8s failures across layers and proposes fixes as PRs (never touches the cluster)

**Body:** (same as HN, shorter; end with a question)
… What failure would you want it to catch that most tools miss?

---

## LinkedIn

Most AI tools for Kubernetes either guess from raw logs or get admin access to "fix" things. I wanted
neither.

So I built NAME: an open-source AI ops layer that
→ finds the real root cause across every layer (apps, Kafka/Redis/Postgres, ingress, logging, GitOps, secrets),
→ proposes the fix as a reviewed Git pull request,
→ and never writes to the cluster.

First real test on my lab: 5 broken apps, 5 correct root causes, 33 seconds, 7x less AI context than raw
kubectl. It also found 4 bugs in my own code that my test data had hidden: real clusters always win.

Open source, works with Claude or a local model. Looking for 3 teams running Kubernetes + GitOps to try it on a
real cluster for free in exchange for feedback. DM me.

#Kubernetes #DevOps #SRE #GitOps #AI #OpenSource
