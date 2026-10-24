# Changelog

## 0.2.0 (unreleased)
Every layer around the apps, data systems and the full fix lifecycle.
- Edge: ingress-nginx (IngressNightmare versions → upgrade PR, retirement, snippet annotations, ModSecurity DetectionOnly → blocking PR, CRS, per-Ingress WAF bypass, outage impact) and Kong (exposed Admin API → ClusterIP PR, plain admin listener, missing KongPlugins, per-pod rate limits).
- Log pipeline: Fluent Bit (node coverage → toleration PR, Retry_Limit/Mem_Buf_Limit → config PR, TLS, inline credentials, undeliverable destination), Fluentd/Vector coverage. Config parsed from ConfigMaps, never returned.
- Routing (Ingress → missing/unready backends, linked to the broken workload) and cert-manager certificates (expired, expiring, renewal failing).
- Multi-edit plans: several fixes in the same file merge into one diff.
- Cluster operations packs: Traefik + Gateway API routes, Argo CD / Flux health, External Secrets / Sealed Secrets (named as root cause of missing Secrets), HPA / KEDA / Karpenter / Cluster Autoscaler, StorageClasses / Longhorn / Rook Ceph, Kyverno / PolicyReports / admission denials, Velero, Prometheus operator, Alertmanager alerts (new `/alertmanager` webhook), metrics-server usage (OOM risk, throttling, rightsizing, capacity), node version skew, pending LoadBalancers, Istio/Linkerd sidecars.
- Cluster service catalog with user-facing impact: CoreDNS, Cilium, Calico, Istio, Linkerd, Argo CD, Flux, ESO, Sealed Secrets, cert-manager, Kyverno, Gatekeeper, KEDA, Karpenter, Cluster Autoscaler, Longhorn, Rook, Velero, Prometheus, Alertmanager, metrics-server, Loki, Promtail (EOL), Alloy, OTel Collector, Traefik, Envoy Gateway, AWS LB controller.
- API discovery before CR listing; controllers without pods are diagnosable.
- Component detection: Kafka (Strimzi), RabbitMQ (operator), OpenSearch/Elasticsearch (operator, ECK), Redis, PostgreSQL (CloudNativePG, Zalando), MongoDB, plus Helm-installed and plain StatefulSets.
- ~25 deterministic component checks: quorum, Kafka replication and min.insync, JVM heap vs limit, PVC state, PDB, spread, auth disabled, external exposure, operator status.
- Dependency graph from env values (values never output) and "Likely root cause" findings that blame the broken dependency, ranked by log evidence.
- Opt-in log signatures (`KUBEPILOT_READ_LOGS`), sanitized, failing containers only.
- New fixes: `add-pdb`, `make-service-internal`, `set-kafka-config`, scoped `restrict-ingress`; edits to operator CRs and Helm values (Argo CD, Flux, values files).
- New tools: `list_components`, `diagnose_component`, `verify_fix`, `plan_revert`. `cluster_health` lists components and likely root causes.
- Security triage: +15 for workloads exposed via LoadBalancer/NodePort.
- `kubepilot ask`: agent loop for local/OpenAI-compatible models (Ollama, LM Studio, vLLM); JSON transcripts. `kubepilot commit`: human-only, TTY-confirmed commit.
- Operator support verified against upstream: Strimzi 1.x `v1` API and KRaft node pools (legacy `v1beta2` still read), OpenSearch operator's new `opensearch.org` group, OT Redis leader/follower topology, busy vs failed operator phases.
- Release workflow (PyPI trusted publishing + GHCR image), `scripts/brand.py` to set the GitHub owner / rename.
- Demo cluster gains a `data` namespace and an `orders` app; optional `make lab-data` for real clusters.

## 0.1.0
First public alpha.
- Diagnosis engine: OOM (rollout-correlated), crash loops, image pull, missing Secret/ConfigMap, unschedulable, probes, nodes.
- Security triage: Falco + Trivy + RBAC + NetworkPolicy correlation with explained scoring; allowlist; platform namespaces hidden by default.
- GitOps remediation: plan → diff → policy guard → approval → branch/PR. Never writes to the cluster.
- MCP server (stdio + Streamable HTTP), CLI, bundled demo (`kubepilot demo`), Falco webhook receiver.
- Validated end to end on a single-node k3s lab with Falco, Trivy Operator and Claude Code.
- Hardening: credential privilege warning, redacted captures, authenticated and size-limited ingest, repo git hooks never run.
