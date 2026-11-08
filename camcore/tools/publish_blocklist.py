#!/usr/bin/env python3
"""Build the CamCore production DNS blocklists from the approved upstream feed.

One build publishes the same domain set in two formats:

- ``blocklist-adblock.txt`` — ``||domain^`` rules. Pi-hole v6 applies each rule
  to the domain and every subdomain. This is the production feed (OPS-1062).
- ``blocklist.txt`` — one exact domain per line, matched exactly by Pi-hole.
  Kept unchanged in format as the rollback feed until OPS-1062 cleanup.
"""

from __future__ import annotations

import json
import os
import urllib.request
from collections import defaultdict
from pathlib import Path

from dns_policy import (
    COMMENT_PREFIXES,
    MAX_SHRINK_FRACTION,
    MIN_PUBLISHED_ENTRIES,
    AllowPolicy,
    adblock_rule,
    feed_domains,
    load_allow_policy,
    load_deny_entries,
    parse_adblock_rule,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "camcore/sources.json"
ALLOWLIST = ROOT / "camcore/allowlist.txt"
DENYLIST = ROOT / "camcore/denylist.txt"
OUTPUT = ROOT / "blocklist.txt"
ADBLOCK_OUTPUT = ROOT / "blocklist-adblock.txt"
MAX_BYTES = 20 * 1024 * 1024
USER_AGENT = "CamCore-DNS-Publisher/1.2 (+https://github.com/Team-CamCore/dns-blocklists)"
UPSTREAM_HEADER_KEYS = ("Version",)


def production_source() -> dict[str, object]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    active = [s for s in manifest["sources"] if s.get("status") == "active" and s.get("deployment") == "production"]
    if len(active) != 1:
        raise RuntimeError(f"Expected exactly one production source, found {len(active)}")
    source = active[0]
    if source.get("id") != "camcore-hagezi-multi-normal":
        raise RuntimeError("Unexpected production source identity")
    return source


def parse_upstream(text: str) -> tuple[set[str], dict[str, str]]:
    """Validate Adblock upstream text and return its domains and selected header values.

    Only ``||domain^`` data lines are accepted. Exceptions (``@@``), modifiers
    (``$...``), plain domains and any other syntax fail the build, so the
    last-known-good feeds are kept.
    """
    domains: set[str] = set()
    header: dict[str, str] = {}
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip().lower()
        if not line:
            continue
        if line.startswith(COMMENT_PREFIXES):
            key, _, value = raw_line.lstrip("#! ").partition(":")
            if key in UPSTREAM_HEADER_KEYS and value.strip():
                header[key] = value.strip()
            continue
        domain = parse_adblock_rule(line)
        if domain is None:
            raise RuntimeError(f"Unexpected upstream entry at line {number}: {raw_line!r}")
        domains.add(domain)
    return domains, header


def fetch_upstream(url: str) -> tuple[set[str], dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.geturl().split(":", 1)[0] != "https":
            raise RuntimeError("Upstream redirected away from HTTPS")
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise RuntimeError("Upstream feed exceeded the 20 MiB safety limit")
    return parse_upstream(raw.decode("utf-8"))


def apply_policy(
    upstream: set[str], allow: AllowPolicy, deny: set[str]
) -> tuple[set[str], dict[str, list[str]]]:
    """Apply CamCore policy and return the output plus upstream names each allow rule removed."""
    removed: dict[str, list[str]] = defaultdict(list)
    output: set[str] = set()
    for domain in upstream | deny:
        rule = allow.matching_rule(domain)
        if rule is None:
            output.add(domain)
        elif domain in upstream:
            removed[rule].append(domain)
    return output, {rule: sorted(names) for rule, names in sorted(removed.items())}


def check_parent_conflicts(domains: set[str], allow: AllowPolicy) -> None:
    """Fail when a published parent would block an allow-listed name through subdomain matching."""
    conflicts = allow.parent_conflicts(domains)
    if conflicts:
        detail = "; ".join(f"{rule} is under blocked {parent}" for rule, parent in conflicts[:10])
        raise RuntimeError(
            f"{len(conflicts)} allow-list rule(s) sit under a published parent domain ({detail}). "
            "Decide whether to remove the parent through the allow-list or accept the block; "
            "the build will not drop a parent automatically"
        )


def render_feeds(domains: set[str], header: dict[str, str]) -> tuple[str, str]:
    """Return the text of the domains (rollback) feed and the Adblock (production) feed."""
    ordered = sorted(domains)
    version = header.get("Version", "unknown")
    domains_feed = [
        "# CamCore DNS Blocklist",
        "# Rollback feed for CamCore-managed Pi-hole resolvers. Exact-match domains.",
        "# Source: HaGeZi Multi NORMAL; CamCore allow/deny policy applied.",
        f"# Upstream version: {version}",
        f"# Entries: {len(domains)}",
        "# Generated automatically. Do not edit this file manually.",
        "",
        *ordered,
    ]
    # Comments use '#' rather than '!' so Pi-hole counts no header line as invalid.
    adblock_feed = [
        "# CamCore DNS Blocklist (Adblock)",
        "# Production feed for CamCore-managed Pi-hole v6 resolvers.",
        "# Each ||domain^ rule blocks the domain and every subdomain.",
        "# Source: HaGeZi Multi NORMAL; CamCore allow/deny policy applied.",
        f"# Upstream version: {version}",
        f"# Entries: {len(domains)}",
        "# Generated automatically. Do not edit this file manually.",
        "",
        *(adblock_rule(domain) for domain in ordered),
    ]
    return "\n".join(domains_feed) + "\n", "\n".join(adblock_feed) + "\n"


def check_size(new_count: int, previous_count: int) -> None:
    """Refuse a build that is implausibly small, so the last-known-good feed is kept."""
    if new_count < MIN_PUBLISHED_ENTRIES:
        raise RuntimeError(
            f"Build produced only {new_count} domains (floor {MIN_PUBLISHED_ENTRIES}); "
            "refusing to replace the last-known-good feed"
        )
    if previous_count and new_count < previous_count * (1 - MAX_SHRINK_FRACTION):
        raise RuntimeError(
            f"Build shrank from {previous_count} to {new_count} domains, more than "
            f"{MAX_SHRINK_FRACTION:.0%}; refusing to publish without review"
        )


def report(removed: dict[str, list[str]], count: int, header: dict[str, str]) -> None:
    """Print a run summary and, inside GitHub Actions, annotate allow-list hits."""
    lines = [
        "## CamCore DNS blocklist build",
        "",
        f"- Published domains: **{count}**",
        f"- Upstream version: `{header.get('Version', 'unknown')}`",
        "",
    ]
    if removed:
        lines += ["### Upstream names kept open by the CamCore allow-list", "", "| Allow rule | Names removed |", "| --- | --- |"]
        for rule, names in removed.items():
            sample = ", ".join(f"`{name}`" for name in names[:10])
            more = f" and {len(names) - 10} more" if len(names) > 10 else ""
            lines.append(f"| `{rule}` | {sample}{more} |")
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(f"::notice title=Allow-list hit::{rule} kept {len(names)} upstream name(s) open: {', '.join(names[:5])}")
    else:
        lines.append("No upstream entry matched the CamCore allow-list.")
    summary = "\n".join(lines) + "\n"
    print(summary)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(summary)


def main() -> int:
    source = production_source()
    upstream_url = source.get("upstream_url")
    if not isinstance(upstream_url, str) or not upstream_url.startswith("https://"):
        raise RuntimeError("Production source must define an HTTPS upstream_url")

    allow = load_allow_policy(ALLOWLIST)
    deny = load_deny_entries(DENYLIST)
    upstream, header = fetch_upstream(upstream_url)
    domains, removed = apply_policy(upstream, allow, deny)

    previous = feed_domains(OUTPUT.read_text(encoding="utf-8")) if OUTPUT.is_file() else []
    check_size(len(domains), len(previous))
    leaked = sorted(domain for domain in domains if allow.permits(domain))
    if leaked:
        raise RuntimeError(f"Allow-listed names reached the output: {leaked[:10]}")
    check_parent_conflicts(domains, allow)

    # Write both feeds to temporary files first so a failure leaves neither half-updated.
    domains_text, adblock_text = render_feeds(domains, header)
    staged = []
    for path, text in ((OUTPUT, domains_text), (ADBLOCK_OUTPUT, adblock_text)):
        temporary = path.with_suffix(".tmp")
        temporary.write_text(text, encoding="utf-8")
        staged.append((temporary, path))
    for temporary, path in staged:
        temporary.replace(path)
    report(removed, len(domains), header)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
