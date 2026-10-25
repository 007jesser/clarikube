"""Built-in policy guard (Kyverno/PSS-"restricted"-inspired) for proposed manifests.

A change is BLOCKED only if it *introduces* a deny-level violation. Violations that already
existed before the change are reported as pre-existing, so kubemedic can fix one problem
without being blocked by unrelated legacy debt — but it can never make things worse.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod"}
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "ALL"}


class Violation(BaseModel, frozen=True):
    rule: str
    level: Literal["deny", "warn"]
    message: str


class PolicyResult(BaseModel):
    rule: str
    level: Literal["deny", "warn"]
    message: str
    status: Literal["introduced", "pre-existing", "resolved"]


def _pod_spec(obj: dict[str, Any]) -> dict[str, Any]:
    spec = obj.get("spec") or {}
    kind = obj.get("kind")
    if kind == "Pod":
        return dict(spec)
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    return dict((spec.get("template") or {}).get("spec") or {})


def check(obj: dict[str, Any]) -> set[Violation]:
    """Evaluate one object. Unknown kinds pass."""
    if obj.get("kind") not in WORKLOAD_KINDS:
        return set()
    v: set[Violation] = set()
    ps = _pod_spec(obj)
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if ps.get(key):
            v.add(Violation(rule="host-namespaces", level="deny", message=f"{key}: true is not allowed"))
    for vol in ps.get("volumes") or []:
        if "hostPath" in vol:
            v.add(Violation(rule="no-hostpath", level="deny", message=f"hostPath volume '{vol.get('name')}'"))
    pod_sc = ps.get("securityContext") or {}
    for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
        name = c.get("name", "?")
        sc = c.get("securityContext") or {}
        if sc.get("privileged"):
            v.add(Violation(rule="no-privileged", level="deny", message=f"'{name}' is privileged"))
        caps = {str(x).upper().removeprefix("CAP_") for x in (sc.get("capabilities") or {}).get("add") or []}
        if caps & DANGEROUS_CAPS:
            v.add(
                Violation(
                    rule="no-dangerous-caps",
                    level="deny",
                    message=f"'{name}' adds {sorted(caps & DANGEROUS_CAPS)}",
                )
            )
        image = str(c.get("image", ""))
        last = image.rsplit("/", 1)[-1]
        if "@sha256:" not in image and (":" not in last or last.endswith(":latest")):
            v.add(Violation(rule="pinned-image", level="deny", message=f"'{name}' uses mutable image '{image}'"))
        res = c.get("resources") or {}
        if not (res.get("limits") or {}).get("memory"):
            v.add(Violation(rule="memory-limit", level="warn", message=f"'{name}' has no memory limit"))
        if sc.get("allowPrivilegeEscalation") is not False:
            v.add(
                Violation(
                    rule="no-priv-escalation",
                    level="warn",
                    message=f"'{name}' does not set allowPrivilegeEscalation: false",
                )
            )
        non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        if user == 0:
            v.add(Violation(rule="non-root", level="deny", message=f"'{name}' sets runAsUser: 0"))
        elif non_root is not True and user is None:
            v.add(Violation(rule="non-root", level="warn", message=f"'{name}' may run as root"))
    return v


def compare(before: dict[str, Any] | None, after: dict[str, Any] | None) -> list[PolicyResult]:
    b = check(before) if before else set()
    a = check(after) if after else set()
    out = [PolicyResult(**x.model_dump(), status="introduced") for x in sorted(a - b, key=str)]
    out += [PolicyResult(**x.model_dump(), status="pre-existing") for x in sorted(a & b, key=str)]
    out += [PolicyResult(**x.model_dump(), status="resolved") for x in sorted(b - a, key=str)]
    return out


def blocking(results: list[PolicyResult]) -> list[PolicyResult]:
    return [r for r in results if r.level == "deny" and r.status == "introduced"]
