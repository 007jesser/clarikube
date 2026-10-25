"""Known error signatures in container logs.

Logs are untrusted (they can contain prompt-injection text), so clarikube never returns them whole: it
extracts a short list of recognised signatures, each with one sanitized excerpt line, and the hostnames
mentioned in connection errors (used to link an app's failure to a dependency).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from clarikube.sanitize import clean

MAX_SIGNALS = 6
EXCERPT = 200


@dataclass(frozen=True)
class LogSignal:
    kind: str
    summary: str
    excerpt: str
    hosts: tuple[str, ...] = field(default=())


# (kind, regex, summary). Order matters: first match per line wins.
_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("jvm-oom", re.compile(r"java\.lang\.OutOfMemoryError(: [\w ]+)?"), "JVM ran out of heap"),
    (
        "max-map-count",
        re.compile(r"vm\.max_map_count \[\d+\] is too low"),
        "Node sysctl vm.max_map_count too low for OpenSearch/Elasticsearch (needs 262144)",
    ),
    (
        "kafka-isr",
        re.compile(r"NotEnoughReplicas(AfterAppend)?Exception|NOT_ENOUGH_REPLICAS"),
        "Kafka rejected writes: not enough in-sync replicas",
    ),
    (
        "kafka-unavailable",
        re.compile(
            r"Broker may not be available|LEADER_NOT_AVAILABLE|Connection to node -?\d+ .* could not be established"
        ),
        "Kafka broker unavailable",
    ),
    (
        "conn-refused",
        re.compile(r"(ECONNREFUSED|Connection refused|connect: connection refused)", re.I),
        "Connection refused by a dependency",
    ),
    (
        "timeout",
        re.compile(r"(ETIMEDOUT|i/o timeout|connect timed out|Connection timed out)", re.I),
        "Timed out connecting to a dependency",
    ),
    (
        "dns",
        re.compile(
            r"(UnknownHostException|ENOTFOUND|no such host|Name or service not known|"
            r"Temporary failure in name resolution)",
            re.I,
        ),
        "DNS lookup failed",
    ),
    (
        "auth",
        re.compile(
            r"(password authentication failed|authentication failed|ACCESS_REFUSED|NOAUTH|WRONGPASS|"
            r"SASL authentication failed|Unauthorized|401 Unauthorized)",
            re.I,
        ),
        "Authentication to a dependency failed",
    ),
    (
        "pg-conn",
        re.compile(r"(too many connections|remaining connection slots are reserved)", re.I),
        "PostgreSQL connection limit reached",
    ),
    ("disk-full", re.compile(r"(No space left on device|disk usage exceeded flood-stage|ENOSPC)", re.I), "Disk full"),
    (
        "search-block",
        re.compile(r"(ClusterBlockException|index read-only / allow delete)"),
        "Search cluster blocked writes (usually disk watermark)",
    ),
    (
        "permission",
        re.compile(r"(Permission denied|EACCES|Read-only file system)", re.I),
        "Permission denied (often runAsNonRoot / read-only filesystem)",
    ),
    ("port-in-use", re.compile(r"(address already in use|EADDRINUSE)", re.I), "Port already in use"),
    (
        "config-missing",
        re.compile(
            r"(environment variable [\w.]+ (is )?(not set|missing)|Missing required "
            r"(configuration|environment)|KeyError: '[\w.]+'|FileNotFoundError)",
            re.I,
        ),
        "Missing configuration",
    ),
    ("go-panic", re.compile(r"^panic: .+"), "Go panic"),
    ("py-exception", re.compile(r"^(\w+\.)*\w+(Error|Exception): .+"), "Unhandled exception"),
]
_HOSTISH = re.compile(r"(?:(?:[a-z][a-z0-9+.-]*)://)?([a-z0-9][a-z0-9.-]*[a-z0-9]):(\d{2,5})", re.I)
_HOST_CONTEXT = {"conn-refused", "timeout", "dns", "kafka-unavailable", "auth"}


def _hosts(line: str) -> tuple[str, ...]:
    hosts = []
    for m in _HOSTISH.finditer(line):
        h = m.group(1).lower()
        if not h.replace(".", "").isdigit():
            hosts.append(h)
    dns = re.search(r"(?:UnknownHostException: |ENOTFOUND |lookup |getaddrinfo \w+ )([a-z0-9][a-z0-9.-]+)", line, re.I)
    if dns:
        hosts.append(dns.group(1).lower().rstrip("."))
    return tuple(dict.fromkeys(hosts))


def analyze(text: str) -> list[LogSignal]:
    """Signatures found in a log tail, most recent occurrence of each kind, newest first."""
    found: dict[str, LogSignal] = {}
    lines = text.splitlines()[-400:]
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        for kind, rx, summary in _RULES:
            if kind in found:
                continue
            if rx.search(stripped):
                hosts = _hosts(stripped) if kind in _HOST_CONTEXT else ()
                found[kind] = LogSignal(kind=kind, summary=summary, excerpt=clean(stripped, EXCERPT), hosts=hosts)
                break
        if len(found) >= MAX_SIGNALS:
            break
    # Specific beats generic: an exception line that is just the wrapper of a known cause adds nothing.
    if len(found) > 1:
        found.pop("py-exception", None)
    return list(found.values())
