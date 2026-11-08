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
    def test_reads_adblock_rules_and_version_header(self) -> None:
        domains, header = publisher.parse_upstream(
            "[Adblock Plus]\n! Title: HaGeZi's Multi NORMAL\n! Version: 2026.1108.0250.15\n"
            "!\n||ads.example^\n||Tracker.Example^\n"
        )
        self.assertEqual(domains, {"ads.example", "tracker.example"})
        self.assertEqual(header, {"Version": "2026.1108.0250.15"})

    def test_rejects_plain_domain_lines(self) -> None:
        with self.assertRaises(RuntimeError):
            publisher.parse_upstream("||ads.example^\ntracker.example\n")

    def test_rejects_exceptions_modifiers_and_wildcards(self) -> None:
        for line in (
            "@@||allowed.example^",
            "||tracker.example^$third-party",
            "||*.example^",
            "||ads.example",
            "|https://ads.example^",
            "||127.0.0.1^",
        ):
            with self.subTest(line=line), self.assertRaises(RuntimeError):
                publisher.parse_upstream(f"||ads.example^\n{line}\n")


class ParentConflictTests(unittest.TestCase):
    def test_fails_when_exact_allow_entry_sits_under_a_listed_parent(self) -> None:
        allow = dns_policy.build_allow_policy(["login.vendor.example"])
        with self.assertRaisesRegex(RuntimeError, "login.vendor.example is under blocked vendor.example"):
            publisher.check_parent_conflicts({"vendor.example", "ads.example"}, allow)

    def test_fails_when_namespace_sits_under_a_listed_parent(self) -> None:
        allow = dns_policy.build_allow_policy(["*.app.vendor.example"])
        with self.assertRaisesRegex(RuntimeError, r"\*\.app\.vendor\.example is under blocked vendor\.example"):
            publisher.check_parent_conflicts({"vendor.example"}, allow)

    def test_never_drops_the_parent_silently(self) -> None:
        allow = dns_policy.build_allow_policy(["login.vendor.example"])
        output, _ = publisher.apply_policy({"vendor.example"}, allow, set())
        self.assertIn("vendor.example", output)

    def test_allows_sibling_and_child_entries(self) -> None:
        allow = dns_policy.build_allow_policy(["login.vendor.example", "*.camcore.au"])
        publisher.check_parent_conflicts(
            {"telemetry.vendor.example", "ads.login.vendor.example", "ads.example"}, allow
        )


class RenderFeedsTests(unittest.TestCase):
    def test_both_feeds_carry_the_same_domains(self) -> None:
        domains = {"b.example", "a.example"}
        plain, adblock = publisher.render_feeds(domains, {"Version": "1"})
        self.assertEqual(dns_policy.feed_domains(plain), ["a.example", "b.example"])
        self.assertEqual(dns_policy.feed_domains(adblock), ["a.example", "b.example"])
        self.assertIn("||a.example^\n||b.example^\n", adblock)
        self.assertIn("# Entries: 2", plain)
        self.assertIn("# Entries: 2", adblock)

    def test_adblock_feed_uses_only_hash_comments(self) -> None:
        _, adblock = publisher.render_feeds({"a.example"}, {})
        for line in adblock.splitlines():
            if line:
                self.assertTrue(line.startswith("#") or (line.startswith("||") and line.endswith("^")), line)


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
