#!/usr/bin/env python3
"""Shared CamCore DNS policy parsing and matching.

The validator, publisher and source-health check all import this module so that
domain syntax, allow-list semantics and production thresholds are defined once.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
WILDCARD_PREFIX = "*."

# Namespaces that must always be present in the allow-list. They cover
# CamCore-owned public and private names and local-only resolver namespaces.
REQUIRED_ALLOW_RULES = (
    "*.camcore.au",
    "*.camcore.network",
    "*.home.arpa",
    "*.lan",
    "*.local",
    "*.localhost",
)

# A published feed below this size is treated as a failed or truncated build.
MIN_PUBLISHED_ENTRIES = 100_000
# A rebuild that shrinks the feed by more than this fraction is held for review.
MAX_SHRINK_FRACTION = 0.20


def is_valid_domain(value: str, min_labels: int = 2) -> bool:
    """Return True for a lower-case, exact DNS name with no scheme, path or wildcard."""
    if not value or value != value.strip() or value != value.lower():
        return False
    if len(value) > 253 or value.startswith(".") or value.endswith("."):
        return False
    if any(token in value for token in ("://", "/", ":", "*", " ")):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    labels = value.split(".")
    return len(labels) >= min_labels and all(LABEL_RE.fullmatch(label) for label in labels)


def parse_rule(value: str, allow_wildcards: bool) -> tuple[str, bool] | None:
    """Parse one list entry into (domain, is_namespace) or None when invalid.

    ``example.com`` matches that exact name only. ``*.example.com`` matches
    ``example.com`` and every name beneath it, and may name a single-label
    namespace such as ``*.lan``.
    """
    if value.startswith(WILDCARD_PREFIX):
        domain = value[len(WILDCARD_PREFIX):]
        if allow_wildcards and is_valid_domain(domain, min_labels=1):
            return domain, True
        return None
    if is_valid_domain(value):
        return value, False
    return None


def covered_by(domain: str, namespace: str) -> bool:
    return domain == namespace or domain.endswith(f".{namespace}")


@dataclass
class AllowPolicy:
    """Exact names and namespaces that the CamCore feed must never contain."""

    exact: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)

    def matching_rule(self, domain: str) -> str | None:
        """Return the allow-list rule that permits ``domain``, or None."""
        if domain in self.exact:
            return domain
        labels = domain.split(".")
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in self.namespaces:
                return f"{WILDCARD_PREFIX}{candidate}"
        return None

    def permits(self, domain: str) -> bool:
        return self.matching_rule(domain) is not None


def read_list_entries(path: Path, allow_wildcards: bool) -> tuple[list[str], list[str]]:
    """Read and validate a CamCore policy list.

    Entries must be sorted within each section. A section is a run of entries
    separated from the next by a blank line or a full-line comment, so related
    service domains can be grouped under a heading.
    """
    entries: list[str] = []
    errors: list[str] = []
    if not path.is_file():
        return entries, [f"Missing domain list: {path}"]
    previous: str | None = None
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            previous = None
            continue
        if raw != value:
            errors.append(f"{path}:{number}: surrounding whitespace is not allowed")
        if parse_rule(value, allow_wildcards) is None:
            kind = "exact domain or *.namespace" if allow_wildcards else "exact domain"
            errors.append(f"{path}:{number}: invalid {kind}: {value!r}")
        if previous is not None and value < previous:
            errors.append(
                f"{path}:{number}: {value!r} must sort before {previous!r}; "
                "entries must be sorted in ascending lexical order within each section"
            )
        entries.append(value)
        previous = value
    for value, count in sorted(Counter(entries).items()):
        if count > 1:
            errors.append(f"{path}: duplicate domain: {value}")
    return entries, errors


def build_allow_policy(entries: list[str]) -> AllowPolicy:
    policy = AllowPolicy()
    for value in entries:
        parsed = parse_rule(value, allow_wildcards=True)
        if parsed is None:
            continue
        domain, is_namespace = parsed
        (policy.namespaces if is_namespace else policy.exact).add(domain)
    return policy


def load_allow_policy(path: Path) -> AllowPolicy:
    entries, errors = read_list_entries(path, allow_wildcards=True)
    if errors:
        raise RuntimeError("Invalid allow-list: " + "; ".join(errors))
    return build_allow_policy(entries)


def load_deny_entries(path: Path) -> set[str]:
    entries, errors = read_list_entries(path, allow_wildcards=False)
    if errors:
        raise RuntimeError("Invalid deny-list: " + "; ".join(errors))
    return set(entries)


def feed_domains(text: str) -> list[str]:
    """Return the data lines of a published CamCore domains feed."""
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    ]
