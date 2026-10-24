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
- Falcosidekick webhook output posts one event per request; `webhook.customHeaders` sets the
  `Authorization` header (format `Key:Value`, comma-separated).
- Default rule priorities: "Terminal shell in container" = Notice, "Read sensitive file untrusted" =
  Warning, "Drop and execute new binary in container" = Critical (rule sets change between releases).

## Operators — verified against upstream source (Oct 2026)
Checked in the operators' repositories (CRD manifests, label constants, status types). Re-check when an
operator ships a new API version.

| Operator | CRD (versions tried in order) | Pod ↔ CR label | Health signal |
|---|---|---|---|
| Strimzi | `kafkas`, `kafkanodepools.kafka.strimzi.io` (`v1`, then `v1beta2`) | `strimzi.io/cluster`, `strimzi.io/pool-name`, `strimzi.io/broker-role`/`controller-role` | `status.conditions[type=Ready]` |
| RabbitMQ cluster operator | `rabbitmqclusters.rabbitmq.com/v1beta1` | `app.kubernetes.io/name=<cluster>` | conditions `AllReplicasReady`, `ClusterAvailable`, `ReconcileSuccess` |
| OpenSearch operator | `opensearchclusters.opensearch.org/v1` (current), `opensearch.opster.io/v1` (deprecated, mirrored — deduplicated) | `opensearch.org/opensearch-cluster` (old: `opster.io/opensearch-cluster`) | `status.phase` RUNNING/PENDING, `status.health` |
| ECK | `elasticsearches.elasticsearch.k8s.elastic.co/v1` | `elasticsearch.k8s.elastic.co/cluster-name` | `status.health`, `status.phase` Ready/ApplyingChanges/MigratingData/Stalled/Invalid |
| CloudNativePG | `clusters.postgresql.cnpg.io/v1` | `cnpg.io/cluster`; role `cnpg.io/instanceRole` (`role` deprecated) | `status.phase` ("Cluster in healthy state"), conditions `Ready` |
| Zalando | `postgresqls.acid.zalan.do/v1` | `cluster-name`, `spilo-role` | `status.PostgresClusterStatus` Running/Creating/Updating/*Failed/Invalid |
| MongoDB community | `mongodbcommunity.mongodbcommunity.mongodb.com/v1` (repo deprecated, moved to mongodb/mongodb-kubernetes, same CRD) | `app` | `status.phase` Running/Pending/Failed |
| OT Redis | `redisclusters`, `redisreplications.redis.redis.opstreelabs.in/v1beta2` | `app=<name>-leader`/`<name>-follower`, `redis_setup_type`, `role` | `status.state` Initializing/Bootstrap/Ready/Failed |

Notes:
- **Strimzi 1.0 removed `v1beta2`** and Strimzi ≥ 0.46 is KRaft-only: replicas, storage, resources and (optionally)
  JVM options live in `KafkaNodePool` resources (`strimzi.io/cluster` label), not in `Kafka.spec.kafka`. Pods are
  `<cluster>-<pool>-<nodeId>`, owned by `StrimziPodSet <cluster>-<pool>`; Services `<cluster>-kafka-bootstrap`,
  `<cluster>-kafka-brokers`. Legacy `spec.kafka.replicas/resources/storage` is still read for old clusters.
- Broker counts (for replication checks) exclude controller-only node pools.
- RedisCluster members = leader replicas + follower replicas (each defaults to `clusterSize`).
- Operator phases are split into *busy* (Creating, Updating, ApplyingChanges, Pending, Initializing… → medium,
  "still reconciling") and *failed* (anything with fail/invalid/stalled/error → high).

## Data-system rules of thumb used by checks
- JVM heap ≤ 75% of the container limit (Kafka); ≤ 50% for OpenSearch/Elasticsearch (page cache).
- Kafka `min.insync.replicas` must be < replication factor to tolerate one broker down; acks=all writes fail
  with `NotEnoughReplicasException` when fewer in-sync replicas than required.
- Quorum systems with an even member count tolerate no more failures than one member fewer.
- Bitnami images: `ALLOW_EMPTY_PASSWORD=yes` disables auth. Redis `--protected-mode no` without
  `requirepass` accepts anyone. PostgreSQL `POSTGRES_HOST_AUTH_METHOD=trust` disables passwords.
- OpenSearch `DISABLE_SECURITY_PLUGIN=true` / Elasticsearch `xpack.security.enabled=false` disable auth and TLS.

## Logs
- `read_namespaced_pod_log(previous=True, tail_lines=200, limit_bytes=65536)`; 400 (no previous
  instance), 403 and 404 are treated as "no logs". Needs `pods/log` `get` (optional ClusterRole).

## Helm values
- Argo CD: `spec.source(s)[].helm.valuesObject` (map), `helm.values` (string, not edited), `helm.valueFiles`
  (resolved relative to `source.path` in the same repo). Release name = `helm.releaseName` or the Application name.
- Flux: `HelmRelease.spec.values`, release name = `spec.releaseName` or `metadata.name`.
- Pods of a Helm release carry `app.kubernetes.io/instance=<release>`.

## MCP
- Built on the official Python SDK **v2** (`mcp.server.mcpserver.MCPServer`; v1's `FastMCP` was renamed).
- Tools carry `readOnlyHint` annotations; plan/commit tools are marked non-read-only.
