from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "camcore" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import dns_policy  # noqa: E402


class DomainValidationTests(unittest.TestCase):
    def test_accepts_exact_lower_case_domains(self) -> None:
        self.assertTrue(dns_policy.is_valid_domain("example.com"))
        self.assertTrue(dns_policy.is_valid_domain("sub-domain.example.net"))
        self.assertTrue(dns_policy.is_valid_domain("xn--bcher-kva.example"))

    def test_rejects_non_domain_inputs(self) -> None:
        invalid = (
            "Example.com",
            "https://example.com",
            "example.com/path",
            "*.example.com",
            "||example.com^",
            "192.0.2.1",
            "localhost",
            "example.com.",
            " example.com",
            "example..com",
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertFalse(dns_policy.is_valid_domain(value))


class RuleParsingTests(unittest.TestCase):
    def test_parses_exact_and_namespace_rules(self) -> None:
        self.assertEqual(dns_policy.parse_rule("plex.tv", True), ("plex.tv", False))
        self.assertEqual(dns_policy.parse_rule("*.plex.direct", True), ("plex.direct", True))
        self.assertEqual(dns_policy.parse_rule("*.lan", True), ("lan", True))

    def test_rejects_namespaces_where_not_allowed_and_malformed_wildcards(self) -> None:
        self.assertIsNone(dns_policy.parse_rule("*.plex.direct", False))
        for value in ("*example.com", "*.*.example.com", "a.*.example.com", "*.", "lan"):
            with self.subTest(value=value):
                self.assertIsNone(dns_policy.parse_rule(value, True))


class AllowPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = dns_policy.build_allow_policy(["*.camcore.au", "*.lan", "plex.tv"])

    def test_namespace_rule_covers_apex_and_subdomains(self) -> None:
        self.assertEqual(self.policy.matching_rule("camcore.au"), "*.camcore.au")
        self.assertEqual(self.policy.matching_rule("plex.camcore.au"), "*.camcore.au")
        self.assertEqual(self.policy.matching_rule("nas.lan"), "*.lan")

    def test_exact_rule_does_not_cover_subdomains(self) -> None:
        self.assertEqual(self.policy.matching_rule("plex.tv"), "plex.tv")
        self.assertIsNone(self.policy.matching_rule("analytics.plex.tv"))

    def test_namespace_rule_does_not_match_lookalike_domains(self) -> None:
        self.assertIsNone(self.policy.matching_rule("notcamcore.au"))
        self.assertIsNone(self.policy.matching_rule("camcore.au.evil.example"))


class ListFileTests(unittest.TestCase):
    def read(self, text: str, allow_wildcards: bool = True) -> tuple[list[str], list[str]]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "list.txt"
            path.write_text(text, encoding="utf-8")
            return dns_policy.read_list_entries(path, allow_wildcards)

    def test_detects_duplicates_and_unsorted_sections(self) -> None:
        entries, errors = self.read("# test\nz.example\na.example\na.example\n")
        self.assertEqual(entries, ["z.example", "a.example", "a.example"])
        self.assertTrue(any("duplicate domain" in error for error in errors))
        self.assertTrue(any("must be sorted" in error for error in errors))

    def test_sorting_is_enforced_per_section(self) -> None:
        _, errors = self.read("# Service B\nb.example\nc.example\n\n# Service A\na.example\n")
        self.assertEqual(errors, [])

    def test_duplicates_are_detected_across_sections(self) -> None:
        _, errors = self.read("# One\na.example\n# Two\na.example\n")
        self.assertTrue(any("duplicate domain: a.example" in error for error in errors))


class RepositoryAllowListTests(unittest.TestCase):
    def test_repository_allow_list_is_valid_and_protects_critical_names(self) -> None:
        policy = dns_policy.load_allow_policy(REPO_ROOT / "camcore/allowlist.txt")
        for name in (
            "camcore.au",
            "portainer.camcore.network",
            "login.microsoftonline.com",
            "enterpriseenrollment.manage.microsoft.com",
            "raw.githubusercontent.com",
            "plex.tv",
            "abc123.def456.plex.direct",
            "uptime.betterstack.com",
            "region1.v2.argotunnel.com",
            "quic.cftunnel.com",
            "dash.cloudflare.com",
        ):
            with self.subTest(name=name):
                self.assertTrue(policy.permits(name))

    def test_repository_allow_list_keeps_known_telemetry_blocked(self) -> None:
        policy = dns_policy.load_allow_policy(REPO_ROOT / "camcore/allowlist.txt")
        for name in (
            "analytics.plex.tv",
            "collector.github.com",
            "metrics.netbird.io",
            "metrics.ubuntu.com",
            "analytics.synology.com",
            "piwik.proxmox.com",
            "metrics.anthropic.com",
            "tr.www.cloudflare.com",
        ):
            with self.subTest(name=name):
                self.assertFalse(policy.permits(name))


if __name__ == "__main__":
    unittest.main()
