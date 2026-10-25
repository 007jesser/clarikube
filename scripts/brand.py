"""Set the GitHub owner and (optionally) rename the project before the first public release.

    python scripts/brand.py --owner jessersallemi                 # replace OWNER placeholders
    python scripts/brand.py --owner jessersallemi --name clarikube  # also rename clarikube -> clarikube

Renames the Python package, CLI, env var prefix (KUBEPILOT_ -> CLARIKUBE_), labels/annotations/branch
prefixes and docs. Run the test suite afterwards. Only touches files tracked by git.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {"uv.lock", "scripts/brand.py"}


def tracked() -> list[Path]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files"], check=True, capture_output=True, text=True).stdout
    return [ROOT / p for p in out.splitlines() if p not in SKIP]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True, help="GitHub user or organisation")
    ap.add_argument("--name", help="new project name (lowercase letters, digits, dashes)")
    args = ap.parse_args()
    name = args.name
    if name and not re.fullmatch(r"[a-z][a-z0-9-]{2,30}", name):
        print("name must be lowercase letters/digits/dashes", file=sys.stderr)
        return 2
    module = name.replace("-", "_") if name else None
    for f in tracked():
        try:
            text = f.read_text()
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        new = text.replace("OWNER/", f"{args.owner}/").replace("ghcr.io/OWNER", f"ghcr.io/{args.owner}")
        if name and module:
            new = new.replace("Clarikube", "".join(p.capitalize() for p in name.split("-")))
            new = new.replace("KUBEPILOT", module.upper())
            new = re.sub(r"(?<![\w-])clarikube(?=\.cli|\.service|\.|\s+import|_)", module, new)  # python modules
            new = new.replace("clarikube", name)
        if new != text:
            f.write_text(new)
    if module:
        src = ROOT / "src" / "clarikube"
        if src.exists():
            subprocess.run(["git", "-C", str(ROOT), "mv", str(src), str(ROOT / "src" / module)], check=True)
    print("done; now run: uv lock && make check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
