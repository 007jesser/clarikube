"""Operator custom resources kubepilot reads (read-only) when the CRDs exist in the cluster.

Each entry: (group, versions to try in order, plural, kind). Missing CRDs or versions (404) and
forbidden ones (403) are skipped: most clusters run only a few of these operators. Verified against
upstream sources in Oct 2026 (see docs/platform-notes.md).
"""

from __future__ import annotations

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
]

CR_GROUPS = {g for g, _, _, _ in OPERATOR_CRDS}
