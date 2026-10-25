"""Label selector and NetworkPolicy coverage semantics (per Kubernetes API docs)."""

from __future__ import annotations

from clarikube.models import LabelSelector, NetworkPolicyInfo, Pod


def matches(sel: LabelSelector, labels: dict[str, str]) -> bool:
    """metav1.LabelSelector semantics. An empty selector matches everything."""
    for k, v in sel.match_labels.items():
        if labels.get(k) != v:
            return False
    for expr in sel.match_expressions:
        key = str(expr.get("key", ""))
        op = str(expr.get("operator", ""))
        values = [str(x) for x in expr.get("values") or []]  # type: ignore[attr-defined]
        present = key in labels
        if op == "In" and not (present and labels[key] in values):
            return False
        if op == "NotIn" and present and labels[key] in values:
            return False
        if op == "Exists" and not present:
            return False
        if op == "DoesNotExist" and present:
            return False
        if op not in ("In", "NotIn", "Exists", "DoesNotExist"):
            return False  # unknown operator: fail closed (treat as non-matching)
    return True


def covering_policies(pod: Pod, policies: list[NetworkPolicyInfo], direction: str) -> list[NetworkPolicyInfo]:
    """Policies in the pod's namespace that select it and govern ``direction`` (Ingress|Egress)."""
    return [
        np
        for np in policies
        if np.namespace == pod.namespace and direction in np.policy_types and matches(np.pod_selector, pod.labels)
    ]
