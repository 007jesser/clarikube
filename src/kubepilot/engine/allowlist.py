"""Noise suppression for known-benign runtime alerts.

Example ``allowlist.yaml``::

    falco:
      - rule: "Read sensitive file untrusted"
        namespace: batch
        image: "docker.io/restic/restic:*"
        reason: "nightly backup reads /etc by design"
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from kubepilot.models import FalcoAlert


class FalcoAllowRule(BaseModel):
    rule: str
    namespace: str = "*"
    pod: str = "*"
    image: str = "*"
    reason: str = ""


class Allowlist(BaseModel):
    falco: list[FalcoAllowRule] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None) -> Allowlist:
        if not path or not Path(path).exists():
            return cls()
        return cls.model_validate(yaml.safe_load(Path(path).read_text()) or {})

    def suppresses(self, alert: FalcoAlert) -> FalcoAllowRule | None:
        for r in self.falco:
            if (
                fnmatchcase(alert.rule, r.rule)
                and fnmatchcase(alert.namespace or "", r.namespace)
                and fnmatchcase(alert.pod or "", r.pod)
                and fnmatchcase(alert.image or "", r.image)
            ):
                return r
        return None
