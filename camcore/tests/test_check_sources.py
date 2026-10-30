from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "camcore" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import check_sources  # noqa: E402
import dns_policy  # noqa: E402


class PlausibleEntryCountTests(unittest.TestCase):
    def test_counts_hosts_entries_and_ignores_comments(self) -> None:
        sample = """# header
0.0.0.0 ads.example
127.0.0.1 tracker.example # comment
:: malware.example
invalid.example
"""
        self.assertEqual(check_sources.plausible_entry_count(sample, "hosts"), 3)

    def test_counts_adblock_entries(self) -> None:
        sample = """! header
||ads.example^
@@||allowed.example^
||tracker.example^$third-party
not-a-filter
"""
        self.assertEqual(check_sources.plausible_entry_count(sample, "adblock"), 2)

    def test_counts_exact_domain_entries(self) -> None:
        sample = """# header
ads.example
sub-domain.tracker.example
https://invalid.example
*.invalid.example
"""
        self.assertEqual(check_sources.plausible_entry_count(sample, "domains"), 2)


class AllowListEnforcementTests(unittest.TestCase):
    def test_reports_feed_entries_that_break_the_allow_list(self) -> None:
        allow = dns_policy.build_allow_policy(["*.microsoftonline.com", "plex.tv"])
        feed = """# CamCore DNS Blocklist
ads.example
analytics.plex.tv
login.microsoftonline.com
plex.tv
"""
        self.assertEqual(
            check_sources.blocked_allowlisted_names(feed, allow),
            ["login.microsoftonline.com", "plex.tv"],
        )

    def test_committed_feed_blocks_no_allow_listed_name(self) -> None:
        allow = dns_policy.load_allow_policy(REPO_ROOT / "camcore/allowlist.txt")
        feed = (REPO_ROOT / "blocklist.txt").read_text(encoding="utf-8")
        self.assertEqual(check_sources.blocked_allowlisted_names(feed, allow), [])


class ProductionSourceSelectionTests(unittest.TestCase):
    def test_selects_only_active_production_records(self) -> None:
        manifest = {
            "sources": [
                {"id": "active", "status": "active", "deployment": "production"},
                {
                    "id": "evaluation",
                    "status": "under-review",
                    "deployment": "evaluation",
                },
                {"id": "retired", "status": "retired", "deployment": "retired"},
                "invalid",
            ]
        }
        selected = check_sources.select_production_sources(manifest)
        self.assertEqual([source["id"] for source in selected], ["active"])


if __name__ == "__main__":
    unittest.main()
