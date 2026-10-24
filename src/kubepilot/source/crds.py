"""Operator custom resources kubepilot reads (read-only) when the CRDs exist in the cluster.

Each entry: (group, version, plural, kind). Missing CRDs are skipped silently: most clusters run
only a few of these operators. Versions are the current storage versions; verify against your
installed operators (docs/platform-notes.md).
"""

from __future__ import annotations

OPERATOR_CRDS: list[tuple[str, str, str, str]] = [
    ("kafka.strimzi.io", "v1beta2", "kafkas", "Kafka"),
    ("kafka.strimzi.io", "v1beta2", "kafkanodepools", "KafkaNodePool"),
    ("rabbitmq.com", "v1beta1", "rabbitmqclusters", "RabbitmqCluster"),
    ("opensearch.opster.io", "v1", "opensearchclusters", "OpenSearchCluster"),
    ("elasticsearch.k8s.elastic.co", "v1", "elasticsearches", "Elasticsearch"),
    ("postgresql.cnpg.io", "v1", "clusters", "Cluster"),
    ("acid.zalan.do", "v1", "postgresqls", "postgresql"),
    ("mongodbcommunity.mongodb.com", "v1", "mongodbcommunity", "MongoDBCommunity"),
    ("redis.redis.opstreelabs.in", "v1beta2", "redisclusters", "RedisCluster"),
    ("redis.redis.opstreelabs.in", "v1beta2", "redisreplications", "RedisReplication"),
    ("argoproj.io", "v1alpha1", "applications", "Application"),
]

CR_GROUPS = {g for g, _, _, _ in OPERATOR_CRDS}
