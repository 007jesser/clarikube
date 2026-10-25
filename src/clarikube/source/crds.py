"""Operator custom resources clarikube reads (read-only) when the CRDs exist in the cluster.

Each entry: (group, versions to try in order, plural, kind). Missing CRDs or versions (404) and
forbidden ones (403) are skipped: most clusters run only a few of these operators. Verified against
upstream sources in Oct 2026 (see docs/platform-notes.md).
"""

from __future__ import annotations

import re

OPERATOR_CRDS: list[tuple[str, tuple[str, ...], str, str]] = [
    # Strimzi 1.0 removed v1beta2; older installs only serve v1beta2.
    ("kafka.strimzi.io", ("v1", "v1beta2"), "kafkas", "Kafka"),
    ("kafka.strimzi.io", ("v1", "v1beta2"), "kafkanodepools", "KafkaNodePool"),
    ("rabbitmq.com", ("v1beta1",), "rabbitmqclusters", "RabbitmqCluster"),
    # OpenSearch operator: opensearch.org is current, opensearch.opster.io is deprecated (kept in sync by it).
    ("opensearch.org", ("v1",), "opensearchclusters", "OpenSearchCluster"),
    ("opensearch.opster.io", ("v1",), "opensearchclusters", "OpenSearchCluster"),
    ("elasticsearch.k8s.elastic.co", ("v1",), "elasticsearches", "Elasticsearch"),
    ("postgresql.cnpg.io", ("v1",), "clusters", "Cluster"),
    ("acid.zalan.do", ("v1",), "postgresqls", "postgresql"),
    ("mongodbcommunity.mongodb.com", ("v1",), "mongodbcommunity", "MongoDBCommunity"),
    ("redis.redis.opstreelabs.in", ("v1beta2",), "redisclusters", "RedisCluster"),
    ("redis.redis.opstreelabs.in", ("v1beta2",), "redisreplications", "RedisReplication"),
    ("argoproj.io", ("v1alpha1",), "applications", "Application"),
    ("cert-manager.io", ("v1",), "certificates", "Certificate"),
    # gateways
    ("traefik.io", ("v1alpha1",), "ingressroutes", "IngressRoute"),
    ("traefik.io", ("v1alpha1",), "middlewares", "Middleware"),
    ("gateway.networking.k8s.io", ("v1", "v1beta1"), "gateways", "Gateway"),
    ("gateway.networking.k8s.io", ("v1", "v1beta1"), "httproutes", "HTTPRoute"),
    # GitOps controllers
    ("kustomize.toolkit.fluxcd.io", ("v1",), "kustomizations", "Kustomization"),
    ("helm.toolkit.fluxcd.io", ("v2", "v2beta2"), "helmreleases", "HelmRelease"),
    ("source.toolkit.fluxcd.io", ("v1", "v1beta2"), "gitrepositories", "GitRepository"),
    ("source.toolkit.fluxcd.io", ("v1", "v1beta2"), "helmrepositories", "HelmRepository"),
    ("source.toolkit.fluxcd.io", ("v1", "v1beta2"), "ocirepositories", "OCIRepository"),
    # secrets
    ("external-secrets.io", ("v1", "v1beta1"), "externalsecrets", "ExternalSecret"),
    ("external-secrets.io", ("v1", "v1beta1"), "secretstores", "SecretStore"),
    ("external-secrets.io", ("v1", "v1beta1"), "clustersecretstores", "ClusterSecretStore"),
    ("bitnami.com", ("v1alpha1",), "sealedsecrets", "SealedSecret"),
    # monitoring, autoscaling, storage
    ("monitoring.coreos.com", ("v1",), "prometheuses", "Prometheus"),
    ("monitoring.coreos.com", ("v1",), "alertmanagers", "Alertmanager"),
    ("keda.sh", ("v1alpha1",), "scaledobjects", "ScaledObject"),
    ("keda.sh", ("v1alpha1",), "scaledjobs", "ScaledJob"),
    ("karpenter.sh", ("v1",), "nodepools", "NodePool"),
    ("karpenter.sh", ("v1",), "nodeclaims", "NodeClaim"),
    ("longhorn.io", ("v1beta2",), "volumes", "Volume"),
    ("ceph.rook.io", ("v1",), "cephclusters", "CephCluster"),
    # policy, backup
    ("kyverno.io", ("v1",), "clusterpolicies", "ClusterPolicy"),
    ("kyverno.io", ("v1",), "policies", "Policy"),
    ("wgpolicyk8s.io", ("v1alpha2",), "policyreports", "PolicyReport"),
    ("wgpolicyk8s.io", ("v1alpha2",), "clusterpolicyreports", "ClusterPolicyReport"),
    ("velero.io", ("v1",), "backups", "Backup"),
    ("velero.io", ("v1",), "schedules", "Schedule"),
    ("velero.io", ("v1",), "backupstoragelocations", "BackupStorageLocation"),
    ("configuration.konghq.com", ("v1",), "kongplugins", "KongPlugin"),
    ("configuration.konghq.com", ("v1",), "kongclusterplugins", "KongClusterPlugin"),
]

CR_GROUPS = {g for g, _, _, _ in OPERATOR_CRDS}

# Pods whose ConfigMaps clarikube reads (config of platform components it checks). Nothing else is fetched.

PLATFORM_IMAGES = re.compile(
    r"fluent-bit|fluentbit|fluentd|timberio/vector|/vector:|ingress-nginx/controller|kong|traefik|grafana/alloy|"
    r"promtail|opentelemetry-collector",
    re.I,
)
