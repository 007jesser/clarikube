"""Change plans: plan → diff → approval → commit on a branch (never applied to the cluster).

Safety properties (each covered by tests):
* a plan expires after ``ttl``;
* commit is refused if the repo HEAD or any touched file changed since planning (stale plan);
* commit is refused if the plan introduces a deny-level policy violation;
* commit requires the approval token issued with the plan (stored hashed), and in
  ``approval_mode="cli"`` additionally a local approval written by ``kubemedic approve``;
* the commit is created in a temporary git worktree, so the user's checkout is never touched;
* dry-run (default) reports what would be committed without writing anything.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import secrets
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from kubemedic.models import WorkloadRef
from kubemedic.policy import PolicyResult, blocking
from kubemedic.remediation import FileChange, RemediationResult

GIT_TIMEOUT = 60


class GitError(Exception):
    pass


def git(repo: Path, *args: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.CalledProcessError as e:
        raise GitError(f"git {' '.join(args)} failed: {e.stderr.strip()}") from e
    return r.stdout.strip()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class PlannedFile(BaseModel):
    path: str
    before_sha: str | None
    after: str
    diff: str
    policy: list[PolicyResult] = Field(default_factory=list)
    deleted: bool = False


class ChangePlan(BaseModel):
    id: str
    workload: WorkloadRef
    created_at: datetime
    expires_at: datetime
    repo_head: str
    base_branch: str
    files: list[PlannedFile]
    applied: list[str]
    manual: list[str]
    notes: list[str]
    blocked: bool
    blocking_reasons: list[str]
    risk: Literal["low", "medium", "high"]
    evidence_summary: str
    token_sha: str
    addresses: list[dict[str, str]] = Field(default_factory=list)  # findings this plan is meant to fix
    baseline: list[str] | None = None  # ids of all findings present when planned (None: older plan)
    reverts: str | None = None  # plan id this plan undoes
    status: Literal["pending", "committed", "rejected", "expired"] = "pending"
    branch: str | None = None
    commit: str | None = None
    pr_url: str | None = None

    def public(self) -> dict[str, object]:
        """What the model/user sees (no token hash)."""
        d = self.model_dump(mode="json", exclude={"token_sha"})
        for f in d["files"]:
            f.pop("after", None)
        return d


class PlanStore:
    def __init__(
        self,
        repo: Path,
        state_dir: Path,
        ttl: timedelta = timedelta(minutes=30),
        approval_mode: Literal["token", "cli"] = "token",
        dry_run: bool = True,
        push: bool = False,
    ) -> None:
        self.repo = repo.resolve()
        self.state_dir = state_dir
        self.ttl = ttl
        self.approval_mode = approval_mode
        self.dry_run = dry_run
        self.push = push
        (state_dir / "plans").mkdir(parents=True, exist_ok=True)
        (state_dir / "approvals").mkdir(parents=True, exist_ok=True)
        self.audit_path = state_dir / "audit.jsonl"

    # ------------------------------------------------------------ persistence / audit

    def _path(self, plan_id: str) -> Path:
        if not plan_id.isalnum():
            raise ValueError("invalid plan id")
        return self.state_dir / "plans" / f"{plan_id}.json"

    def save(self, plan: ChangePlan) -> None:
        self._path(plan.id).write_text(plan.model_dump_json(indent=2))

    def get(self, plan_id: str) -> ChangePlan:
        p = self._path(plan_id)
        if not p.exists():
            raise KeyError(f"unknown plan {plan_id}")
        return ChangePlan.model_validate_json(p.read_text())

    def all_plans(self) -> list[ChangePlan]:
        plans = [ChangePlan.model_validate_json(p.read_text()) for p in (self.state_dir / "plans").glob("*.json")]
        return sorted(plans, key=lambda p: p.created_at, reverse=True)

    def audit(self, event: str, **data: object) -> None:
        rec = {"time": datetime.now(UTC).isoformat(), "event": event, **data}
        with self.audit_path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def history(self, limit: int = 20) -> list[dict[str, object]]:
        if not self.audit_path.exists():
            return []
        lines = self.audit_path.read_text().splitlines()[-limit:]
        return [json.loads(x) for x in lines]

    # ------------------------------------------------------------ planning

    def create(
        self,
        wl: WorkloadRef,
        result: RemediationResult,
        evidence_summary: str,
        now: datetime | None = None,
        addresses: list[dict[str, str]] | None = None,
        reverts: str | None = None,
        baseline: list[str] | None = None,
    ) -> tuple[ChangePlan, str]:
        now = now or datetime.now(UTC)
        head = git(self.repo, "rev-parse", "HEAD")
        branch = git(self.repo, "rev-parse", "--abbrev-ref", "HEAD")
        files = [self._planned(c) for c in result.changes]
        blockers = [f"{f.path}: {r.message} [{r.rule}]" for f in files for r in blocking(f.policy)]
        token = secrets.token_urlsafe(24)
        plan = ChangePlan(
            id=secrets.token_hex(6),
            workload=wl,
            created_at=now,
            expires_at=now + self.ttl,
            repo_head=head,
            base_branch=branch,
            files=files,
            applied=result.applied,
            manual=result.manual,
            notes=result.notes,
            blocked=bool(blockers) or not files,
            blocking_reasons=blockers or ([] if files else ["no automatable change for this workload"]),
            risk=self._risk(result),
            evidence_summary=evidence_summary,
            token_sha=_sha(token),
            addresses=addresses or [],
            reverts=reverts,
            baseline=baseline,
        )
        self.save(plan)
        self.audit(
            "plan_created",
            plan_id=plan.id,
            workload=wl.key,
            files=[f.path for f in files],
            blocked=plan.blocked,
        )
        return plan, token

    @staticmethod
    def _planned(c: FileChange) -> PlannedFile:
        return PlannedFile(
            path=c.path,
            before_sha=_sha(c.before) if c.before is not None else None,
            after=c.after,
            diff=c.diff(),
            policy=c.policy,
            deleted=c.deleted,
        )

    @staticmethod
    def _risk(result: RemediationResult) -> Literal["low", "medium", "high"]:
        text = " ".join(result.applied).lower()
        if "isolate" in text or "revert" in text:
            return "high"
        if any(k in text for k in ("image", "networkpolicy", "runasnonroot")):
            return "medium"
        return "low"

    # ------------------------------------------------------------ approval / commit

    def approve_cli(self, plan_id: str) -> None:
        """Called by the local `kubemedic approve` command (a human at a terminal)."""
        plan = self.get(plan_id)
        (self.state_dir / "approvals" / plan.id).write_text(datetime.now(UTC).isoformat())
        self.audit("plan_approved_cli", plan_id=plan.id)

    def reject(self, plan_id: str) -> ChangePlan:
        plan = self.get(plan_id)
        plan.status = "rejected"
        self.save(plan)
        self.audit("plan_rejected", plan_id=plan.id)
        return plan

    def _check(self, plan: ChangePlan, token: str | None, now: datetime) -> None:
        """token=None means a human confirmed at a terminal (``kubemedic commit``); all other checks apply."""
        if plan.status != "pending":
            raise PermissionError(f"plan is {plan.status}")
        if now > plan.expires_at:
            plan.status = "expired"
            self.save(plan)
            raise PermissionError("plan expired — create a new plan")
        if token is not None and not hmac.compare_digest(_sha(token), plan.token_sha):
            self.audit("commit_denied", plan_id=plan.id, reason="bad token")
            raise PermissionError("invalid approval token")
        if token is not None and self.approval_mode == "cli" and not (self.state_dir / "approvals" / plan.id).exists():
            raise PermissionError(f"awaiting human approval: run `kubemedic approve {plan.id}` in a terminal")
        if plan.blocked:
            raise PermissionError("plan is blocked: " + "; ".join(plan.blocking_reasons))
        if git(self.repo, "rev-parse", "HEAD") != plan.repo_head:
            raise PermissionError("stale plan: repository HEAD moved since planning — re-plan")
        for f in plan.files:
            p = self.repo / f.path
            current = _sha(p.read_text()) if p.exists() else None
            if current != f.before_sha:
                raise PermissionError(f"stale plan: {f.path} changed since planning — re-plan")

    def commit(self, plan_id: str, token: str | None, now: datetime | None = None, human: bool = False) -> ChangePlan:
        """Commit with the plan's approval token, or with ``human=True`` (and token None) when a person confirmed
        it interactively at a terminal."""
        if token is None and not human:
            raise PermissionError("approval token required")
        now = now or datetime.now(UTC)
        plan = self.get(plan_id)
        self._check(plan, token, now)
        if human:
            self.audit("plan_approved_terminal", plan_id=plan.id)
        branch = f"kubemedic/{plan.workload.name}-{plan.id}"
        if self.dry_run:
            self.audit("commit_dry_run", plan_id=plan.id, branch=branch)
            plan.branch = branch
            return plan
        tmp = Path(tempfile.mkdtemp(prefix="kubemedic-wt-"))
        wt = tmp / "wt"
        try:
            git(self.repo, "worktree", "add", "-b", branch, str(wt), plan.repo_head)
            for f in plan.files:
                target = (wt / f.path).resolve()
                if wt.resolve() not in target.parents:
                    raise PermissionError(f"refusing to write outside the repo: {f.path}")
                if f.deleted:
                    git(wt, "rm", "-q", "--", f.path)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f.after)
                git(wt, "add", "--", f.path)
            msg = self._message(plan)
            git(
                wt,
                "-c",
                "user.name=kubemedic",
                "-c",
                "user.email=kubemedic@localhost",
                "commit",
                "--no-verify",
                "-m",
                msg,
            )
            plan.commit = git(wt, "rev-parse", "HEAD")
            plan.branch = branch
            if self.push:
                git(wt, "push", "-u", "origin", branch)
                plan.pr_url = self._open_pr(wt, plan, msg)
        finally:
            with contextlib.suppress(GitError):
                git(self.repo, "worktree", "remove", "--force", str(wt))
            shutil.rmtree(tmp, ignore_errors=True)
            with contextlib.suppress(GitError):
                git(self.repo, "worktree", "prune")
        plan.status = "committed"
        self.save(plan)
        self.audit("plan_committed", plan_id=plan.id, branch=branch, commit=plan.commit, pr=plan.pr_url)
        return plan

    @staticmethod
    def _message(plan: ChangePlan) -> str:
        verb = f"revert plan {plan.reverts} on" if plan.reverts else "fix"
        title = f"kubemedic: {verb} {plan.workload.kind.lower()} {plan.workload.namespace}/{plan.workload.name}"
        body = ["", "Why:", plan.evidence_summary, "", "Changes:"] + [f"- {a}" for a in plan.applied]
        if plan.notes:
            body += ["", "Reviewer notes:"] + [f"- {n}" for n in plan.notes]
        body += ["", f"Plan-Id: {plan.id}"]
        return "\n".join([title, *body])

    @staticmethod
    def _open_pr(wt: Path, plan: ChangePlan, msg: str) -> str | None:
        if not shutil.which("gh"):
            return None
        title, _, body = msg.partition("\n")
        try:
            r = subprocess.run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--base",
                    plan.base_branch,
                    "--head",
                    plan.branch or "",
                    "--title",
                    title,
                    "--body",
                    body.strip(),
                ],
                cwd=wt,
                check=True,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None
        return r.stdout.strip().splitlines()[-1] if r.stdout.strip() else None


# ---------------------------------------------------------------- after the commit: merged? revert


def _ref_exists(repo: Path, ref: str) -> bool:
    try:
        git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        return True
    except GitError:
        return False


def _show(repo: Path, ref: str, path: str) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{path}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        ).stdout
    except subprocess.CalledProcessError:
        return None


def merge_state(repo: Path, plan: ChangePlan) -> dict[str, str]:
    """Is the plan's commit in the base branch? Uses local refs only (run `git fetch` to refresh)."""
    if plan.status != "committed" or not plan.commit:
        return {"state": "not-committed", "detail": f"plan status is {plan.status}"}
    for ref in (plan.base_branch, f"origin/{plan.base_branch}"):
        if not _ref_exists(repo, ref):
            continue
        try:
            git(repo, "merge-base", "--is-ancestor", plan.commit, ref)
            return {"state": "merged", "detail": f"commit {plan.commit[:10]} is in {ref}"}
        except GitError:
            pass
        # Squash / rebase merges rewrite the commit: compare file contents instead.
        same = all(
            (_show(repo, ref, f.path) is None) if f.deleted else (_show(repo, ref, f.path) == f.after)
            for f in plan.files
        )
        if same and plan.files:
            return {"state": "merged", "detail": f"{ref} contains the planned file contents (squash/rebase merge)"}
    return {
        "state": "not-merged",
        "detail": f"branch {plan.branch} is not in {plan.base_branch} yet "
        "(based on local refs; `git fetch` to refresh)",
    }


def revert_changes(repo: Path, plan: ChangePlan) -> list[FileChange]:
    """File changes that undo a committed plan on top of the current HEAD (computed in a throwaway worktree)."""
    if not plan.commit:
        raise ValueError(f"plan {plan.id} has no commit to revert")
    tmp = Path(tempfile.mkdtemp(prefix="kubemedic-rv-"))
    wt = tmp / "wt"
    try:
        git(repo, "worktree", "add", "--detach", str(wt), "HEAD")
        try:
            git(wt, "revert", "--no-commit", plan.commit)
        except GitError as e:
            raise ValueError(f"plan {plan.id} cannot be reverted cleanly on HEAD (later edits overlap): {e}") from e
        out: list[FileChange] = []
        for f in plan.files:
            cur_path = repo / f.path
            before = cur_path.read_text() if cur_path.exists() else None
            reverted = wt / f.path
            if reverted.exists():
                after = reverted.read_text()
                if after != before:
                    out.append(FileChange(path=f.path, before=before, after=after))
            elif before is not None:
                out.append(FileChange(path=f.path, before=before, after="", deleted=True))
        return out
    finally:
        with contextlib.suppress(GitError):
            git(repo, "worktree", "remove", "--force", str(wt))
        shutil.rmtree(tmp, ignore_errors=True)
        with contextlib.suppress(GitError):
            git(repo, "worktree", "prune")
