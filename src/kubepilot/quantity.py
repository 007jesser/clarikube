"""Kubernetes resource.Quantity parsing/formatting (the subset we need)."""

from __future__ import annotations

import re
from decimal import Decimal

_BINARY = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60}
_DECIMAL = {
    "n": Decimal("1e-9"),
    "u": Decimal("1e-6"),
    "m": Decimal("1e-3"),
    "": Decimal(1),
    "k": Decimal("1e3"),
    "M": Decimal("1e6"),
    "G": Decimal("1e9"),
    "T": Decimal("1e12"),
    "P": Decimal("1e15"),
    "E": Decimal("1e18"),
}
_RE = re.compile(r"^([+-]?[0-9.]+)([eE][+-]?[0-9]+)?(Ki|Mi|Gi|Ti|Pi|Ei|n|u|m|k|M|G|T|P|E)?$")


def parse(q: str | int | float) -> Decimal:
    """Parse a quantity into base units (bytes for memory, cores for CPU)."""
    s = str(q).strip()
    m = _RE.match(s)
    if not m:
        raise ValueError(f"invalid quantity: {q!r}")
    number, exp, suffix = m.group(1), m.group(2) or "", m.group(3) or ""
    value = Decimal(number + exp)
    if suffix in _BINARY:
        return value * _BINARY[suffix]
    return value * _DECIMAL[suffix]


def format_memory(num_bytes: Decimal | int) -> str:
    """Format bytes using the largest binary suffix that keeps an integer, rounding up to Mi."""
    b = int(Decimal(num_bytes).to_integral_value(rounding="ROUND_CEILING"))
    mi = -(-b // 2**20)  # ceil to MiB
    if mi % 1024 == 0:
        return f"{mi // 1024}Gi"
    return f"{mi}Mi"


def format_cpu(cores: Decimal) -> str:
    milli = int((cores * 1000).to_integral_value(rounding="ROUND_CEILING"))
    if milli % 1000 == 0:
        return str(milli // 1000)
    return f"{milli}m"
