#!/usr/bin/env python3
"""Perform a bounded, read-only health check of approved production DNS sources.

For each production feed, and its rollback feed while one is published, this
confirms that the feed is reachable over HTTPS, contains a plausible number of
entries, and blocks none of the names in the CamCore allow-list. For an Adblock
feed it also confirms that no parent of an allow-listed name is listed, because
a ``||parent^`` rule would block the allow-listed name through subdomain matching.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from dns_policy import MIN_PUBLISHED_ENTRIES, AllowPolicy, feed_domains, load_allow_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "camcore/sources.json"
ALLOWLIST_PATH = REPO_ROOT / "camcore/allowlist.txt"
READ_LIMIT = 20 * 1024 * 1024
USER_AGENT = "CamCore-DNS-Source-Health/1.2 (+https://github.com/Team-CamCore/dns-blocklists)"

HOSTS_LINE_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::)\s+([A-Za-z0-9.-]+)(?:\s|$)"
)
ADBLOCK_LINE_RE = re.compile(r"^\|\|([A-Za-z0-9.-]+)\^")
DOMAIN_LINE_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def plausible_entry_count(text: str, source_format: str) -> int:
    """Count entries in supported source formats, ignoring comments and junk."""
    count = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", "[")):
            continue
        if source_format == "hosts" and HOSTS_LINE_RE.match(line):
            count += 1
        elif source_format == "adblock" and ADBLOCK_LINE_RE.match(line):
            count += 1
        elif source_format == "domains" and DOMAIN_LINE_RE.fullmatch(line):
            count += 1
    return count


def blocked_allowlisted_names(text: str, allow: AllowPolicy) -> list[str]:
    """Return feed entries that the CamCore allow-list says must never be blocked."""
    return sorted(domain for domain in feed_domains(text) if allow.permits(domain.lower()))


def blocked_allowlisted_parents(text: str, allow: AllowPolicy) -> list[str]:
    """Return "rule under parent" descriptions for allow-listed names an Adblock feed would block."""
    listed = {domain.lower() for domain in feed_domains(text)}
    return [f"{rule} under {parent}" for rule, parent in allow.parent_conflicts(listed)]


def feeds_to_check(source: dict[str, object]) -> list[tuple[str, str]]:
    """Return (url, format) for the production feed and any rollback feed."""
    feeds = [(str(source["url"]), str(source["format"]))]
    if source.get("rollback_url"):
        feeds.append((str(source["rollback_url"]), str(source.get("rollback_format", "domains"))))
    return feeds


def select_production_sources(manifest: dict[str, object]) -> list[dict[str, object]]:
    """Return only records explicitly active in production."""
    sources = manifest.get("sources")
    if not isinstance(sources, list):
        return []
    return [
        source
        for source in sources
        if isinstance(source, dict)
        and source.get("status") == "active"
        and source.get("deployment") == "production"
    ]


def check_source(source: dict[str, object], allow: AllowPolicy) -> list[str]:
    """Check every feed a production source publishes and return success summaries."""
    source_id = str(source["id"])
    return [check_feed(source_id, url, source_format, allow) for url, source_format in feeds_to_check(source)]


def check_feed(source_id: str, url: str, source_format: str, allow: AllowPolicy) -> str:
    """Fetch one feed and return a human-readable success summary."""

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,application/octet-stream;q=0.9,*/*;q=0.1",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )

    with urllib.request.urlopen(request, timeout=60) as response:
        status = getattr(response, "status", response.getcode())
        if status != 200:
            raise RuntimeError(f"unexpected HTTP status {status}")
        final_url = response.geturl()
        if urlparse(final_url).scheme != "https":
            raise RuntimeError("source redirected to a non-HTTPS endpoint")
        raw = response.read(READ_LIMIT + 1)

    if not raw:
        raise RuntimeError("source returned no data")
    if len(raw) > READ_LIMIT:
        raise RuntimeError("source exceeded the 20 MiB safety limit")
    if b"\x00" in raw:
        raise RuntimeError("source appears to contain binary data")

    text = raw.decode("utf-8", errors="replace")
    count = plausible_entry_count(text, source_format)
    if count < MIN_PUBLISHED_ENTRIES:
        raise RuntimeError(
            f"source contained only {count} plausible {source_format} entries "
            f"(floor {MIN_PUBLISHED_ENTRIES})"
        )
    blocked = blocked_allowlisted_names(text, allow)
    if blocked:
        raise RuntimeError(
            f"{url} blocks {len(blocked)} allow-listed name(s): {', '.join(blocked[:10])}"
        )
    if source_format == "adblock":
        parents = blocked_allowlisted_parents(text, allow)
        if parents:
            raise RuntimeError(
                f"{url} blocks {len(parents)} allow-listed name(s) through a listed parent: "
                f"{', '.join(parents[:10])}"
            )

    return f"{source_id}: {url} reachable; {count} {source_format} entries; no allow-listed name is blocked"


def main() -> int:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        allow = load_allow_policy(ALLOWLIST_PATH)
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"Unable to read CamCore DNS policy: {exc}", file=sys.stderr)
        return 1

    sources = select_production_sources(manifest)
    if not sources:
        print("No approved production sources were found.", file=sys.stderr)
        return 1

    failures: list[str] = []
    for source in sources:
        try:
            for summary in check_source(source, allow):
                print(summary)
        except (KeyError, OSError, RuntimeError, urllib.error.URLError) as exc:
            failures.append(f"{source.get('id', '<unknown>')}: {exc}")

    if failures:
        print("CamCore DNS source-health check failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    noun = "source" if len(sources) == 1 else "sources"
    print(f"All {len(sources)} approved production {noun} passed the health check.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
