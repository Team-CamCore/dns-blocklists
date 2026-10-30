from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / "camcore" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import validate_repository as validator  # noqa: E402


class LocalPolicyValidationTests(unittest.TestCase):
    def write_policy(self, root: Path, allow: str, deny: str) -> None:
        (root / "camcore").mkdir(parents=True, exist_ok=True)
        (root / "camcore/allowlist.txt").write_text(allow, encoding="utf-8")
        (root / "camcore/denylist.txt").write_text(deny, encoding="utf-8")

    def required_rules(self) -> str:
        return "\n".join(sorted(validator.REQUIRED_ALLOW_RULES)) + "\n"

    def test_requires_camcore_namespaces(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write_policy(root, "*.camcore.au\n", "")
            errors = validator.validate_local_policy(root)
        self.assertTrue(any("*.camcore.network" in error for error in errors))

    def test_rejects_deny_entry_covered_by_allow_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write_policy(root, self.required_rules(), "files.camcore.au\n")
            errors = validator.validate_local_policy(root)
        self.assertTrue(any("conflicts with allow-list rule *.camcore.au" in error for error in errors))

    def test_rejects_namespace_in_deny_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.write_policy(root, self.required_rules(), "*.example.com\n")
            errors = validator.validate_local_policy(root)
        self.assertTrue(any("invalid exact domain" in error for error in errors))


class UrlValidationTests(unittest.TestCase):
    def test_rejects_private_and_credential_bearing_urls(self) -> None:
        private_errors = validator.validate_public_https_url(
            "https://127.0.0.1/list.txt", "source"
        )
        credential_errors = validator.validate_public_https_url(
            "https://user:password@example.com/list.txt", "source"
        )
        self.assertTrue(any("non-public IP" in error for error in private_errors))
        self.assertTrue(
            any("embedded credentials" in error for error in credential_errors)
        )


class ManifestValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (REPO_ROOT / "camcore/sources.json").read_text(encoding="utf-8")
        )

    def validate_manifest_data(self, manifest: dict[str, object]) -> list[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sources.json"
            path.write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return validator.validate_manifest(path)

    def test_manifest_rejects_unapproved_production_source(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["sources"][0]["id"] = "unapproved-source"
        errors = self.validate_manifest_data(manifest)
        self.assertTrue(any("production source IDs must be exactly" in error for error in errors))

    def test_manifest_rejects_changed_production_endpoint(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["sources"][0]["url"] = "https://example.com/hosts"
        errors = self.validate_manifest_data(manifest)
        self.assertTrue(any("must use url=" in error for error in errors))

    def test_manifest_rejects_active_evaluation_source(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["sources"][1]["status"] = "active"
        errors = self.validate_manifest_data(manifest)
        self.assertTrue(any("requires deployment 'production'" in error for error in errors))


class WorkflowSecurityTests(unittest.TestCase):
    def test_rejects_tagged_action_and_write_permission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for relative in validator.WORKFLOW_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    """name: test
on: workflow_dispatch
permissions:
  contents: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
                    encoding="utf-8",
                )
            errors = validator.validate_workflow_security(root)

        self.assertTrue(any("read-only" in error for error in errors))
        self.assertTrue(any("40-character commit SHA" in error for error in errors))
        self.assertTrue(any("credentials must not persist" in error for error in errors))


class RepositoryValidationTests(unittest.TestCase):
    def test_forbidden_upstream_path_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            forbidden = root / ".github/workflows/release.yml"
            forbidden.parent.mkdir(parents=True, exist_ok=True)
            forbidden.write_text("name: unsafe\n", encoding="utf-8")
            errors = validator.validate_required_content(root)

        self.assertTrue(any("Forbidden upstream path" in error for error in errors))

    def test_current_repository_passes_offline_validation(self) -> None:
        self.assertEqual(validator.validate_repository(REPO_ROOT), [])


if __name__ == "__main__":
    unittest.main()
