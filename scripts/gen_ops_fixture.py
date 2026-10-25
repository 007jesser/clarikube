"""Generates src/kubemedic/demo/cluster/ops.yaml: cluster services and operations tooling with realistic failures."""

import sys

import yaml

docs = []


def add(*objs):
    docs.extend(objs)


def pod(
    name,
    ns,
    owner_kind,
    owner,
    image,
    labels,
    ready=True,
    node="kind-worker",
    containers=None,
    phase="Running",
    limits=None,
    requests=None,
    args=None,
):
    cs = containers or [
        {
            "name": owner.split("-")[0] if owner else "main",
            "image": image,
            **({"args": args} if args else {}),
            "resources": {**({"limits": limits} if limits else {}), **({"requests": requests} if requests else {})},
        }
    ]
    statuses = [
        {
            "name": c["name"],
            "ready": c.get("_ready", ready),
            "restartCount": 0,
            "state": {"running": {"startedAt": "2026-10-01T10:00:00Z"}}
            if c.get("_ready", ready)
            else {"waiting": {"reason": c.get("_reason", "CrashLoopBackOff")}},
        }
        for c in cs
    ]
    for c in cs:
        c.pop("_ready", None)
        c.pop("_reason", None)
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": labels,
            **(
                {"ownerReferences": [{"apiVersion": "apps/v1", "kind": owner_kind, "name": owner, "controller": True}]}
                if owner
                else {}
            ),
        },
        "spec": {"nodeName": node, "containers": cs},
        "status": {"phase": phase, "containerStatuses": statuses},
    }


def deploy(name, ns, image, labels, replicas=1, ready=None, args=None, kind="Deployment", limits=None):
    ready = replicas if ready is None else ready
    spec = {"replicas": replicas} if kind != "DaemonSet" else {}
    status = (
        {"replicas": replicas, "readyReplicas": ready}
        if kind != "DaemonSet"
        else {"desiredNumberScheduled": replicas, "numberReady": ready}
    )
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": ns, "labels": labels},
        "spec": {
            **spec,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "containers": [
                        {
                            "name": name.split("-")[0],
                            "image": image,
                            **({"args": args} if args else {}),
                            "resources": {"limits": limits or {"memory": "256Mi"}},
                        }
                    ]
                },
            },
        },
        "status": status,
    }


def rs(name, ns, owner, image):
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": name,
            "namespace": ns,
            "annotations": {"deployment.kubernetes.io/revision": "1"},
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": owner, "controller": True}],
        },
        "spec": {"template": {"spec": {"containers": [{"name": owner, "image": image}]}}},
    }


# ---------------------------------------------------------------- namespaces
add(
    *[
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": n, **({"labels": {"istio-injection": "enabled"}} if n == "mesh-demo" else {})},
        }
        for n in (
            "default",
            "kube-system",
            "shop",
            "data",
            "ingress-nginx",
            "kong",
            "logging",
            "monitoring",
            "argocd",
            "flux-system",
            "external-secrets",
            "velero",
            "istio-system",
            "mesh-demo",
            "longhorn-system",
            "karpenter",
            "falco",
            "trivy-system",
            "batch",
        )
    ]
)

# ---------------------------------------------------------------- network: CoreDNS (single replica), Cilium (agent down on one node)
lbl = {"k8s-app": "kube-dns"}
add(
    deploy("coredns", "kube-system", "registry.k8s.io/coredns/coredns:v1.12.0", lbl),
    pod(
        "coredns-7db6d8ff4d-abcde",
        "kube-system",
        "ReplicaSet",
        "coredns-7db6d8ff4d",
        "registry.k8s.io/coredns/coredns:v1.12.0",
        lbl,
    ),
    rs("coredns-7db6d8ff4d", "kube-system", "coredns", "registry.k8s.io/coredns/coredns:v1.12.0"),
)
cl = {"k8s-app": "cilium"}
ds = deploy("cilium", "kube-system", "quay.io/cilium/cilium:v1.17.4", cl, replicas=3, ready=2, kind="DaemonSet")
ds["spec"]["template"]["spec"]["tolerations"] = [{"operator": "Exists"}]
add(ds)
for i, (node, ok) in enumerate((("kind-control-plane", True), ("kind-worker", True), ("kind-worker2", False))):
    add(
        pod(
            f"cilium-{'abc'[i]}x{i}q",
            "kube-system",
            "DaemonSet",
            "cilium",
            "quay.io/cilium/cilium:v1.17.4",
            cl,
            ready=ok,
            node=node,
            containers=[
                {
                    "name": "cilium-agent",
                    "image": "quay.io/cilium/cilium:v1.17.4",
                    "_ready": ok,
                    "_reason": "CrashLoopBackOff",
                }
            ],
        )
    )

# ---------------------------------------------------------------- edge: Traefik (k3s style) with insecure dashboard exposed
tl = {"app.kubernetes.io/name": "traefik", "app.kubernetes.io/instance": "traefik-kube-system"}
targs = [
    "--entrypoints.web.address=:8000",
    "--entrypoints.websecure.address=:8443",
    "--api.insecure=true",
    "--providers.kubernetescrd",
]
add(
    deploy("traefik", "kube-system", "rancher/mirrored-library-traefik:3.3.6", tl, args=targs),
    pod(
        "traefik-5d7f8c9b6-tr4fk",
        "kube-system",
        "ReplicaSet",
        "traefik-5d7f8c9b6",
        "rancher/mirrored-library-traefik:3.3.6",
        tl,
        args=targs,
        containers=[{"name": "traefik", "image": "rancher/mirrored-library-traefik:3.3.6", "args": targs}],
    ),
    rs("traefik-5d7f8c9b6", "kube-system", "traefik", "rancher/mirrored-library-traefik:3.3.6"),
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "traefik", "namespace": "kube-system"},
        "spec": {
            "type": "LoadBalancer",
            "selector": tl,
            "ports": [
                {"name": "web", "port": 80, "targetPort": "8000"},
                {"name": "websecure", "port": 443, "targetPort": "8443"},
                {"name": "traefik", "port": 8080, "targetPort": "8080"},
            ],
        },
        "status": {"loadBalancer": {"ingress": [{"ip": "172.18.0.2"}]}},
    },
    {
        "apiVersion": "traefik.io/v1alpha1",
        "kind": "IngressRoute",
        "metadata": {"name": "admin", "namespace": "shop"},
        "spec": {
            "entryPoints": ["websecure"],
            "routes": [
                {
                    "match": "Host(`admin.example.com`)",
                    "kind": "Rule",
                    "middlewares": [{"name": "basic-auth"}],
                    "services": [{"name": "admin-ui", "port": 80}],
                }
            ],
        },
    },
)

# ---------------------------------------------------------------- LoadBalancer stuck pending
add(
    {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "partner-api", "namespace": "shop"},
        "spec": {"type": "LoadBalancer", "selector": {"app": "api"}, "ports": [{"port": 443}]},
        "status": {"loadBalancer": {}},
    },
    {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"name": "partner-api.1", "namespace": "shop"},
        "type": "Warning",
        "reason": "SyncLoadBalancerFailed",
        "message": "Error syncing load balancer: failed to ensure load balancer: no available IPs in pool",
        "involvedObject": {"kind": "Service", "name": "partner-api", "namespace": "shop"},
        "count": 14,
        "lastTimestamp": "2026-10-23T09:58:00Z",
    },
)

# ---------------------------------------------------------------- Gateway API
add(
    {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": {"name": "public", "namespace": "shop"},
        "spec": {
            "gatewayClassName": "eg",
            "listeners": [
                {"name": "https", "port": 443, "protocol": "HTTPS", "allowedRoutes": {"namespaces": {"from": "Same"}}}
            ],
        },
        "status": {
            "conditions": [
                {"type": "Accepted", "status": "True", "reason": "Accepted"},
                {
                    "type": "Programmed",
                    "status": "False",
                    "reason": "AddressNotAssigned",
                    "message": "No addresses have been assigned to the Gateway",
                },
            ],
            "listeners": [
                {
                    "name": "https",
                    "conditions": [
                        {
                            "type": "ResolvedRefs",
                            "status": "False",
                            "reason": "InvalidCertificateRef",
                            "message": "Secret shop/public-tls does not exist",
                        }
                    ],
                }
            ],
        },
    },
    {
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {"name": "reviews", "namespace": "data"},
        "spec": {
            "parentRefs": [{"name": "public", "namespace": "shop"}],
            "hostnames": ["reviews.example.com"],
            "rules": [{"backendRefs": [{"name": "reviews", "port": 8080}]}],
        },
        "status": {
            "parents": [
                {
                    "parentRef": {"name": "public", "namespace": "shop"},
                    "controllerName": "gateway.envoyproxy.io/gatewayclass-controller",
                    "conditions": [
                        {
                            "type": "Accepted",
                            "status": "False",
                            "reason": "NotAllowedByListeners",
                            "message": "No listeners included by this parent ref allowed this attachment.",
                        },
                        {
                            "type": "ResolvedRefs",
                            "status": "False",
                            "reason": "BackendNotFound",
                            "message": "service data/reviews not found",
                        },
                    ],
                }
            ]
        },
    },
)

# ---------------------------------------------------------------- GitOps: Argo CD + Flux
add(
    {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": "data-tier", "namespace": "argocd"},
        "spec": {
            "destination": {"namespace": "data", "server": "https://kubernetes.default.svc"},
            "syncPolicy": {"automated": {"prune": True}},
        },
        "status": {
            "sync": {"status": "OutOfSync"},
            "health": {"status": "Degraded"},
            "operationState": {
                "phase": "Failed",
                "message": 'one or more objects failed to apply, reason: PersistentVolumeClaim "data-events-broker-2" is invalid: spec: Forbidden: spec is immutable after creation',
            },
        },
    },
    {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": "legacy-cms", "namespace": "argocd"},
        "spec": {"destination": {"namespace": "default"}},
        "status": {"sync": {"status": "OutOfSync"}, "health": {"status": "Healthy"}},
    },
    {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {"name": "platform", "namespace": "flux-system"},
        "spec": {"interval": "10m", "path": "./platform", "sourceRef": {"kind": "GitRepository", "name": "infra"}},
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "False",
                    "reason": "ArtifactFailed",
                    "message": "Source artifact not found, retrying in 30s",
                }
            ]
        },
    },
    {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "GitRepository",
        "metadata": {"name": "infra", "namespace": "flux-system"},
        "spec": {"url": "ssh://git@github.com/acme/infra"},
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "False",
                    "reason": "GitOperationFailed",
                    "message": "failed to checkout and determine revision: unable to clone: ssh: handshake failed: knownhosts: key mismatch",
                }
            ]
        },
    },
    {
        "apiVersion": "helm.toolkit.fluxcd.io/v2",
        "kind": "HelmRelease",
        "metadata": {"name": "grafana", "namespace": "monitoring"},
        "spec": {"suspend": True, "chart": {"spec": {"chart": "grafana"}}},
        "status": {},
    },
)

# ---------------------------------------------------------------- secrets: ESO (root cause of shop/api), Sealed Secrets
add(
    {
        "apiVersion": "external-secrets.io/v1",
        "kind": "ExternalSecret",
        "metadata": {"name": "api-db-credentials", "namespace": "shop"},
        "spec": {
            "secretStoreRef": {"kind": "ClusterSecretStore", "name": "vault"},
            "target": {"name": "api-db-credentials"},
            "data": [{"secretKey": "password", "remoteRef": {"key": "prod/shop/api-db", "property": "password"}}],
        },
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "False",
                    "reason": "SecretSyncedError",
                    "message": "could not get secret data from provider: cannot read secret data from Vault: Error making API request. Code: 403. Errors: * permission denied",
                }
            ]
        },
    },
    {
        "apiVersion": "external-secrets.io/v1",
        "kind": "ClusterSecretStore",
        "metadata": {"name": "vault"},
        "spec": {"provider": {"vault": {"server": "https://vault.example.com"}}},
        "status": {
            "conditions": [{"type": "Ready", "status": "True", "reason": "Valid", "message": "store validated"}]
        },
    },
    {
        "apiVersion": "bitnami.com/v1alpha1",
        "kind": "SealedSecret",
        "metadata": {"name": "payment-keys", "namespace": "shop"},
        "spec": {"encryptedData": {"api-key": "AgB4xKZ...truncated..."}},
        "status": {
            "conditions": [
                {
                    "type": "Synced",
                    "status": "False",
                    "reason": "ErrUnsealFailed",
                    "message": "no key could decrypt secret (api-key)",
                }
            ]
        },
    },
)

# ---------------------------------------------------------------- autoscaling: HPA, KEDA, Karpenter, Cluster Autoscaler
add(
    {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": "checkout", "namespace": "shop"},
        "spec": {
            "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "checkout"},
            "minReplicas": 2,
            "maxReplicas": 10,
        },
        "status": {
            "currentReplicas": 2,
            "desiredReplicas": 2,
            "conditions": [
                {"type": "AbleToScale", "status": "True", "reason": "SucceededGetScale"},
                {
                    "type": "ScalingActive",
                    "status": "False",
                    "reason": "FailedGetResourceMetric",
                    "message": "the HPA was unable to compute the replica count: failed to get cpu utilization: missing request for cpu in container checkout",
                },
            ],
        },
    },
    {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": "frontend", "namespace": "shop"},
        "spec": {
            "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "frontend"},
            "minReplicas": 1,
            "maxReplicas": 1,
        },
        "status": {
            "currentReplicas": 1,
            "desiredReplicas": 1,
            "conditions": [
                {"type": "AbleToScale", "status": "True"},
                {"type": "ScalingActive", "status": "True"},
                {
                    "type": "ScalingLimited",
                    "status": "True",
                    "reason": "TooManyReplicas",
                    "message": "the desired replica count is more than the maximum replica count",
                },
            ],
        },
    },
    {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "ScaledObject",
        "metadata": {"name": "worker-queue", "namespace": "shop"},
        "spec": {"scaleTargetRef": {"name": "worker"}, "triggers": [{"type": "rabbitmq"}]},
        "status": {
            "conditions": [
                {
                    "type": "Ready",
                    "status": "False",
                    "reason": "ScaledObjectCheckFailed",
                    "message": "error establishing rabbitmq connection: dial tcp: lookup queue.data on 10.96.0.10:53: no such host",
                },
                {"type": "Active", "status": "False"},
            ]
        },
    },
    {
        "apiVersion": "karpenter.sh/v1",
        "kind": "NodePool",
        "metadata": {"name": "default"},
        "spec": {
            "limits": {"cpu": "16", "memory": "64Gi"},
            "template": {"spec": {"nodeClassRef": {"name": "default"}}},
        },
        "status": {
            "resources": {"cpu": "16", "memory": "48Gi", "nodes": "4"},
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    },
    {
        "apiVersion": "karpenter.sh/v1",
        "kind": "NodeClaim",
        "metadata": {"name": "default-x7k2p"},
        "status": {
            "conditions": [
                {
                    "type": "Launched",
                    "status": "False",
                    "reason": "InsufficientCapacity",
                    "message": "creating instance, insufficient capacity, all requested instance types were unavailable during launch",
                }
            ]
        },
    },
    {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"name": "worker-6b7c8d9e1-q1w2e.ca", "namespace": "shop"},
        "type": "Normal",
        "reason": "NotTriggerScaleUp",
        "message": "pod didn't trigger scale-up: 2 max node group size reached, 1 Insufficient memory",
        "involvedObject": {"kind": "Pod", "name": "worker-6b7c8d9e1-q1w2e", "namespace": "shop"},
        "count": 31,
        "lastTimestamp": "2026-10-23T09:59:00Z",
    },
)

# ---------------------------------------------------------------- storage: Kafka's class was deleted; Longhorn degraded
add(
    {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": {"name": "standard", "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}},
        "provisioner": "rancher.io/local-path",
        "volumeBindingMode": "WaitForFirstConsumer",
    },
    {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": {"name": "longhorn"},
        "provisioner": "driver.longhorn.io",
    },
    {
        "apiVersion": "longhorn.io/v1beta2",
        "kind": "Volume",
        "metadata": {"name": "pvc-4f1c2a9e", "namespace": "longhorn-system"},
        "spec": {"numberOfReplicas": 3},
        "status": {"state": "attached", "robustness": "degraded"},
    },
)

# ---------------------------------------------------------------- policy: Kyverno blocks a deployment; PolicyReport fails payment-api
add(
    {
        "apiVersion": "kyverno.io/v1",
        "kind": "ClusterPolicy",
        "metadata": {"name": "require-run-as-nonroot"},
        "spec": {"validationFailureAction": "Enforce"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]},
    },
    {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "recommendations", "namespace": "shop", "labels": {"app": "recommendations"}},
        "spec": {
            "replicas": 2,
            "selector": {"matchLabels": {"app": "recommendations"}},
            "template": {
                "metadata": {"labels": {"app": "recommendations"}},
                "spec": {
                    "containers": [
                        {"name": "recommendations", "image": "registry.example.com/shop/recommendations:0.9.0"}
                    ]
                },
            },
        },
        "status": {"replicas": 0, "readyReplicas": 0},
    },
    rs("recommendations-6d9f7c5b8", "shop", "recommendations", "registry.example.com/shop/recommendations:0.9.0"),
    {
        "apiVersion": "v1",
        "kind": "Event",
        "metadata": {"name": "recommendations-6d9f7c5b8.1", "namespace": "shop"},
        "type": "Warning",
        "reason": "FailedCreate",
        "message": "Error creating: admission webhook \"validate.kyverno.svc-fail\" denied the request: resource Pod/shop/recommendations-6d9f7c5b8-xxxxx was blocked due to the following policies require-run-as-nonroot: run-as-non-root: 'validation error: Running as root is not allowed. Set runAsNonRoot to true.'",
        "involvedObject": {"kind": "ReplicaSet", "name": "recommendations-6d9f7c5b8", "namespace": "shop"},
        "count": 22,
        "lastTimestamp": "2026-10-23T09:57:00Z",
    },
    {
        "apiVersion": "wgpolicyk8s.io/v1alpha2",
        "kind": "PolicyReport",
        "metadata": {"name": "a1b2c3d4", "namespace": "shop"},
        "scope": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "payment-api", "namespace": "shop"},
        "results": [
            {
                "policy": "require-run-as-nonroot",
                "rule": "run-as-non-root",
                "result": "fail",
                "severity": "high",
                "source": "kyverno",
                "message": "validation error: Running as root is not allowed.",
            },
            {"policy": "disallow-latest-tag", "rule": "require-image-tag", "result": "pass", "source": "kyverno"},
        ],
        "summary": {"fail": 1, "pass": 1},
    },
)

# ---------------------------------------------------------------- backups: Velero location down, stale schedule
add(
    {
        "apiVersion": "velero.io/v1",
        "kind": "BackupStorageLocation",
        "metadata": {"name": "default", "namespace": "velero"},
        "spec": {"provider": "aws", "objectStorage": {"bucket": "acme-backups"}},
        "status": {
            "phase": "Unavailable",
            "message": 'BackupStorageLocation "default" is unavailable: rpc error: code = Unknown desc = AccessDenied: Access Denied',
        },
    },
    {
        "apiVersion": "velero.io/v1",
        "kind": "Schedule",
        "metadata": {"name": "daily", "namespace": "velero"},
        "spec": {"schedule": "0 2 * * *"},
        "status": {"phase": "Enabled", "lastBackup": "2026-10-13T02:00:00Z"},
    },
    {
        "apiVersion": "velero.io/v1",
        "kind": "Backup",
        "metadata": {
            "name": "daily-20261013020000",
            "namespace": "velero",
            "labels": {"velero.io/schedule-name": "daily"},
        },
        "status": {"phase": "PartiallyFailed", "startTimestamp": "2026-10-13T02:00:00Z", "errors": 3},
    },
)

# ---------------------------------------------------------------- monitoring: prometheus-operator, Alertmanager down, metrics-server usage
add(
    {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "Prometheus",
        "metadata": {"name": "k8s", "namespace": "monitoring"},
        "status": {"conditions": [{"type": "Available", "status": "True"}, {"type": "Reconciled", "status": "True"}]},
    },
    {
        "apiVersion": "monitoring.coreos.com/v1",
        "kind": "Alertmanager",
        "metadata": {"name": "main", "namespace": "monitoring"},
        "status": {
            "conditions": [
                {
                    "type": "Available",
                    "status": "False",
                    "reason": "NoPodReady",
                    "message": "0/1 pods ready: alertmanager-main-0 CrashLoopBackOff (invalid config: missing receiver 'pagerduty')",
                }
            ]
        },
    },
)
ml = {"k8s-app": "metrics-server"}
add(
    deploy("metrics-server", "kube-system", "registry.k8s.io/metrics-server/metrics-server:v0.7.2", ml),
    pod(
        "metrics-server-6c9b8f7d5-ms1",
        "kube-system",
        "ReplicaSet",
        "metrics-server-6c9b8f7d5",
        "registry.k8s.io/metrics-server/metrics-server:v0.7.2",
        ml,
    ),
    rs(
        "metrics-server-6c9b8f7d5",
        "kube-system",
        "metrics-server",
        "registry.k8s.io/metrics-server/metrics-server:v0.7.2",
    ),
)


def pm(ns, pod_, containers):
    return {
        "apiVersion": "metrics.k8s.io/v1beta1",
        "kind": "PodMetrics",
        "metadata": {"name": pod_, "namespace": ns},
        "window": "30s",
        "containers": [{"name": n, "usage": {"cpu": c, "memory": m}} for n, c, m in containers],
    }


add(
    pm("kong", "kong-gateway-5f6c7d8b9-abcd1", [("proxy", "180m", "975Mi")]),
    pm("kong", "kong-gateway-5f6c7d8b9-efgh2", [("proxy", "150m", "610Mi")]),
    pm("data", "queue-server-0", [("rabbitmq", "40m", "130Mi")]),
    pm("data", "queue-server-1", [("rabbitmq", "35m", "121Mi")]),
    pm("shop", "payment-api-5f7b8c9d4-x2k9p", [("payment-api", "990m", "200Mi")]),
)

# ---------------------------------------------------------------- mesh: injection on, one workload outside the mesh, one proxy failing
add(
    deploy("istiod", "istio-system", "docker.io/istio/pilot:1.26.1", {"app": "istiod"}),
    pod(
        "istiod-7f9c8d6b5-is1",
        "istio-system",
        "ReplicaSet",
        "istiod-7f9c8d6b5",
        "docker.io/istio/pilot:1.26.1",
        {"app": "istiod"},
    ),
    rs("istiod-7f9c8d6b5", "istio-system", "istiod", "docker.io/istio/pilot:1.26.1"),
    pod(
        "details-v1-5d8c7b9f6-d1",
        "mesh-demo",
        "ReplicaSet",
        "details-v1-5d8c7b9f6",
        "",
        {"app": "details"},
        containers=[{"name": "details", "image": "docker.io/istio/examples-bookinfo-details-v1:1.20.2"}],
    ),
    rs("details-v1-5d8c7b9f6", "mesh-demo", "details-v1", "docker.io/istio/examples-bookinfo-details-v1:1.20.2"),
    pod(
        "ratings-v1-6b7c8d9e0-r1",
        "mesh-demo",
        "ReplicaSet",
        "ratings-v1-6b7c8d9e0",
        "",
        {"app": "ratings"},
        containers=[
            {"name": "ratings", "image": "docker.io/istio/examples-bookinfo-ratings-v1:1.20.2"},
            {"name": "istio-proxy", "image": "docker.io/istio/proxyv2:1.26.1", "_ready": False, "_reason": "Running"},
        ],
    ),
    rs("ratings-v1-6b7c8d9e0", "mesh-demo", "ratings-v1", "docker.io/istio/examples-bookinfo-ratings-v1:1.20.2"),
)

# ---------------------------------------------------------------- telemetry: Promtail (EOL) still running
pl = {"app.kubernetes.io/name": "promtail"}
pds = deploy("promtail", "logging", "docker.io/grafana/promtail:3.0.0", pl, replicas=3, kind="DaemonSet")
pds["spec"]["template"]["spec"]["tolerations"] = [{"operator": "Exists"}]
add(
    pds,
    *[
        pod(
            f"promtail-{n[-1]}p{i}",
            "logging",
            "DaemonSet",
            "promtail",
            "docker.io/grafana/promtail:3.0.0",
            pl,
            node=n,
            containers=[{"name": "promtail", "image": "docker.io/grafana/promtail:3.0.0"}],
        )
        for i, n in enumerate(("kind-control-plane", "kind-worker", "kind-worker2"))
    ],
)

header = "# Cluster services and operations tooling with realistic failures (generated by scripts/gen_ops_fixture.py)\n"
sys.stdout.write(header + yaml.safe_dump_all(docs, sort_keys=False, width=200))
