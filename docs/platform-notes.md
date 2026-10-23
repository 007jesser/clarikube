# Platform notes (verify against your versions)

Assumptions the code relies on. Items marked **verify** were written from documentation knowledge and
have not yet been checked against a live cluster in this repo's CI.

## Kubernetes
- Pods are linked to Deployments through `ownerReferences` → ReplicaSet → Deployment; CronJob pods
  through Job → CronJob. Controller ref (`controller: true`) is preferred.
- Rollout history = ReplicaSets owned by the Deployment, ordered by annotation
  `deployment.kubernetes.io/revision`.
- OOM kills appear as `lastState.terminated.reason: OOMKilled`, exit code 137.
- Unschedulable pods: condition `PodScheduled=False, reason=Unschedulable` with the scheduler message.
- NetworkPolicy `policyTypes` defaulting: `Ingress` always, plus `Egress` if egress rules exist.
- Label selector operators: In, NotIn, Exists, DoesNotExist. Unknown operators fail closed.
- RBAC: a RoleBinding to a ClusterRole grants those rules only inside the binding's namespace.
  ServiceAccounts also match groups `system:serviceaccounts`, `system:serviceaccounts:<ns>`,
  `system:authenticated`. Aggregated ClusterRoles are read with their controller-filled rules.
- List responses from the Python client omit `kind` on items; `KubeSource` sets it.
- Events: both `core/v1` (`involvedObject`, `firstTimestamp`/`lastTimestamp`, `count`) and
  `events.k8s.io/v1` (`regarding`, `note`, `series`) shapes are normalized.

## Trivy Operator — **verify**
- CRD `vulnerabilityreports.aquasecurity.github.io/v1alpha1`.
- Labels: `trivy-operator.resource.kind|name|namespace`, `trivy-operator.container.name`.
  For Deployments the scanned resource is the **ReplicaSet**; kubepilot maps it to the Deployment.
- Fields: `report.artifact.repository|tag`, `report.registry.server`,
  `report.vulnerabilities[].vulnerabilityID|resource|installedVersion|fixedVersion|severity|title|score`.

## Falco / Falcosidekick — **verify**
- Falco JSON: `time`, `rule`, `priority`, `output`, `output_fields`, `tags`.
- Kubernetes fields used: `k8s.ns.name`, `k8s.pod.name`, `container.name`,
  `container.image.repository`, `container.image.tag`.
- Falcosidekick webhook output posts one event per request; `webhook.customheaders` sets the
  `Authorization` header (format `Key:Value`, comma-separated).
- Default rule priorities: "Terminal shell in container" = Notice, "Read sensitive file untrusted" =
  Warning, "Drop and execute new binary in container" = Critical (rule sets change between releases).

## MCP
- Built on the official Python SDK **v2** (`mcp.server.mcpserver.MCPServer`; v1's `FastMCP` was renamed).
- Tools carry `readOnlyHint` annotations; plan/commit tools are marked non-read-only.
