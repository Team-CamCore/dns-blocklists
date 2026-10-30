from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "camcore" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import dns_policy  # noqa: E402
import publish_blocklist as publisher  # noqa: E402


class ParseUpstreamTests(unittest.TestCase):
    def test_reads_domains_and_version_header(self) -> None:
        domains, header = publisher.parse_upstream(
            "# Title: HaGeZi's Multi NORMAL\n# Version: 2026.1029.0937.53\n\nads.example\nTracker.Example\n"
        )
        self.assertEqual(domains, {"ads.example", "tracker.example"})
        self.assertEqual(header, {"Version": "2026.1029.0937.53"})

    def test_rejects_unexpected_upstream_syntax(self) -> None:
        with self.assertRaises(RuntimeError):
            publisher.parse_upstream("ads.example\n||tracker.example^\n")


class ApplyPolicyTests(unittest.TestCase):
    def test_allow_rules_remove_upstream_names_and_report_them(self) -> None:
        allow = dns_policy.build_allow_policy(["*.camcore.au", "plex.tv"])
        upstream = {"ads.example", "plex.tv", "analytics.plex.tv", "x.camcore.au"}
        output, removed = publisher.apply_policy(upstream, allow, {"bad.example"})
        self.assertEqual(output, {"ads.example", "analytics.plex.tv", "bad.example"})
        self.assertEqual(removed, {"*.camcore.au": ["x.camcore.au"], "plex.tv": ["plex.tv"]})

    def test_allow_rule_wins_over_deny_entry(self) -> None:
        allow = dns_policy.build_allow_policy(["*.camcore.au"])
        output, removed = publisher.apply_policy(set(), allow, {"plex.camcore.au"})
        self.assertEqual(output, set())
        self.assertEqual(removed, {})


class SizeGuardTests(unittest.TestCase):
    def test_rejects_build_below_floor(self) -> None:
        with self.assertRaises(RuntimeError):
            publisher.check_size(dns_policy.MIN_PUBLISHED_ENTRIES - 1, 0)

    def test_rejects_sharp_shrink(self) -> None:
        with self.assertRaises(RuntimeError):
            publisher.check_size(120_000, 172_000)

    def test_accepts_normal_variation(self) -> None:
        publisher.check_size(165_000, 172_000)
        publisher.check_size(180_000, 172_000)


if __name__ == "__main__":
    unittest.main()
