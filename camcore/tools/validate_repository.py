#!/usr/bin/env python3
"""Validate the CamCore DNS policy repository without network access."""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = (
    ".editorconfig", ".gitattributes", ".gitignore", "README.md", "NOTICE.md",
    "CONTRIBUTING.md", "SECURITY.md", "LICENSE", "blocklist.txt",
    "docs/OPERATIONS.md", "docs/REPOSITORY-SETTINGS.md", "docs/UPSTREAM.md",
    "camcore/README.md", "camcore/sources.json", "camcore/allowlist.txt",
    "camcore/denylist.txt", "camcore/tools/validate_repository.py",
    "camcore/tools/check_sources.py", "camcore/tools/publish_blocklist.py",
    "camcore/tests/test_validate_repository.py", "camcore/tests/test_check_sources.py",
    ".github/CODEOWNERS", ".github/dependabot.yml",
    ".github/pull_request_template.md", ".github/ISSUE_TEMPLATE/config.yml",
    ".github/workflows/camcore-validate.yml",
    ".github/workflows/camcore-source-health.yml",
    ".github/workflows/camcore-publish.yml",
)
FORBIDDEN_DEFAULT_BRANCH_PATHS = (
    "adblock", "adguard", "controld", "dnsmasq", "ips", "rpz", "share",
    "wildcard", "sources.md", ".github/workflows/release.yml",
    ".github/workflows/alreadyincluded.yml", ".github/workflows/deaddomain.yml",
    ".github/workflows/fixed-pending-release.yml", ".github/workflows/ignored.yml",
    ".github/workflows/malicious-scam-phishing.yml", ".github/workflows/notworthit.yml",
    ".github/ISSUE_TEMPLATE/allowlist-request.yml",
    ".github/ISSUE_TEMPLATE/denylist-request.yml",
    ".github/ISSUE_TEMPLATE/miscellaneous.yml",
)
WORKFLOW_PATHS = (
    Path(".github/workflows/camcore-validate.yml"),
    Path(".github/workflows/camcore-source-health.yml"),
)
PUBLISH_WORKFLOW = Path(".github/workflows/camcore-publish.yml")
CANONICAL_DESCRIPTION = (
    "CamCore is a privately owned and operated family technology network that "
    "delivers secure, reliable and professionally managed digital services for "
    "the Cameron household, Cameron-Media and associated family operations."
)
APPROVED_PRODUCTION_SOURCES = {
    "camcore-hagezi-multi-normal": {
        "format": "domains",
        "url": "https://raw.githubusercontent.com/Team-CamCore/dns-blocklists/main/blocklist.txt",
        "upstream_repository": "https://github.com/hagezi/dns-blocklists",
        "licence": "GPL-3.0",
    }
}
STATUS_DEPLOYMENT = {
    "active": "production",
    "under-review": "evaluation",
    "retired": "retired",
}
PROTECTED_SUFFIXES = (
    "camcore.au", "camcore.network", "localhost", "local", "lan", "home.arpa"
)
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ACTION_REF_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses:\s*[^@\s]+@([^\s#]+)")
WRITE_PERMISSION_RE = re.compile(
    r"(?mi)^\s*(?:actions|checks|contents|deployments|discussions|id-token|issues|"
    r"packages|pages|pull-requests|repository-projects|security-events|statuses):"
    r"\s*write\s*(?:#.*)?$"
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)"
        r"[ \t]*[:=][ \t]*[\"']?[A-Za-z0-9_./+=:-]{12,}"
    ),
)
TEXT_SUFFIXES = {"", ".md", ".txt", ".json", ".py", ".yml", ".yaml"}


def is_valid_domain(value: str) -> bool:
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
    return len(labels) >= 2 and all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def read_domain_entries(path: Path) -> tuple[list[str], list[str]]:
    entries: list[str] = []
    errors: list[str] = []
    if not path.is_file():
        return entries, [f"Missing domain list: {path}"]
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        if raw != value:
            errors.append(f"{path}:{number}: surrounding whitespace is not allowed")
        if not is_valid_domain(value):
            errors.append(f"{path}:{number}: invalid exact domain: {value!r}")
        entries.append(value)
    for value, count in sorted(Counter(entries).items()):
        if count > 1:
            errors.append(f"{path}: duplicate domain: {value}")
    if entries != sorted(entries):
        errors.append(f"{path}: entries must be sorted in ascending lexical order")
    return entries, errors


def validate_public_https_url(raw_url: object, label: str) -> list[str]:
    if not isinstance(raw_url, str):
        return [f"{label} must be a string"]
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    errors: list[str] = []
    if parsed.scheme != "https" or not parsed.netloc or not host:
        return [f"{label} must be an absolute HTTPS URL"]
    if parsed.username or parsed.password:
        errors.append(f"{label} must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        errors.append(f"{label} must not contain a query string or fragment")
    if host == "localhost" or host.endswith((".local", ".internal")):
        errors.append(f"{label} must use a public hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            errors.append(f"{label} must use a fully qualified public hostname")
    else:
        if not address.is_global:
            errors.append(f"{label} must not target a non-public IP address")
    return errors


def validate_manifest(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except FileNotFoundError:
        return [f"Missing source manifest: {path}"]
    except json.JSONDecodeError as exc:
        return [f"{path}: invalid JSON: {exc}"]

    if data.get("schema_version") != 1:
        errors.append(f"{path}: schema_version must be 1")
    policy = data.get("policy")
    expected_policy = {
        "mode": "minimal",
        "production_change_requires_review": True,
        "source_failure_behaviour": "retain-last-known-good",
    }
    if not isinstance(policy, dict):
        errors.append(f"{path}: policy must be an object")
    else:
        for key, expected in expected_policy.items():
            if policy.get(key) != expected:
                errors.append(f"{path}: policy.{key} must be {expected!r}")
        if not isinstance(policy.get("name"), str) or not policy["name"].strip():
            errors.append(f"{path}: policy.name must be a non-empty string")

    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        return errors + [f"{path}: sources must be a non-empty array"]

    ids: set[str] = set()
    urls: set[str] = set()
    production: dict[str, dict[str, object]] = {}
    required = {
        "id", "name", "status", "deployment", "format", "url",
        "upstream_repository", "purpose", "licence",
    }
    for index, source in enumerate(sources):
        label = f"{path}: sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{label} must be an object")
            continue
        missing = sorted(required - source.keys())
        if missing:
            errors.append(f"{label}: missing keys: {', '.join(missing)}")
        source_id = source.get("id")
        if not isinstance(source_id, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", source_id):
            errors.append(f"{label}: id must be lower-case kebab-case")
        elif source_id in ids:
            errors.append(f"{label}: duplicate id: {source_id}")
        else:
            ids.add(source_id)
        status = source.get("status")
        deployment = source.get("deployment")
        if status not in STATUS_DEPLOYMENT:
            errors.append(f"{label}: invalid status: {status!r}")
        elif deployment != STATUS_DEPLOYMENT[status]:
            errors.append(f"{label}: status {status!r} requires deployment {STATUS_DEPLOYMENT[status]!r}")
        if source.get("format") not in {"hosts", "adblock", "domains"}:
            errors.append(f"{label}: invalid format: {source.get('format')!r}")
        source_url = source.get("url")
        errors.extend(validate_public_https_url(source_url, f"{label}: url"))
        errors.extend(validate_public_https_url(source.get("upstream_repository"), f"{label}: upstream_repository"))
        if "upstream_url" in source:
            errors.extend(validate_public_https_url(source.get("upstream_url"), f"{label}: upstream_url"))
        if isinstance(source_url, str):
            if source_url in urls:
                errors.append(f"{label}: duplicate source URL: {source_url}")
            urls.add(source_url)
        for key in ("name", "purpose", "licence"):
            if not isinstance(source.get(key), str) or not source[key].strip():
                errors.append(f"{label}: {key} must be a non-empty string")
        if status == "active" and deployment == "production" and isinstance(source_id, str):
            production[source_id] = source

    expected_ids = set(APPROVED_PRODUCTION_SOURCES)
    if set(production) != expected_ids:
        errors.append(f"{path}: production source IDs must be exactly {sorted(expected_ids)}, found {sorted(production)}")
    for source_id, expected in APPROVED_PRODUCTION_SOURCES.items():
        source = production.get(source_id)
        if source:
            for key, value in expected.items():
                if source.get(key) != value:
                    errors.append(f"{path}: production source {source_id!r} must use {key}={value!r}")
    if raw != json.dumps(data, indent=2, ensure_ascii=False) + "\n":
        errors.append(f"{path}: JSON must use canonical two-space formatting and a final newline")
    return errors


def _validate_action_pins(relative: Path, text: str) -> list[str]:
    errors: list[str] = []
    if "actions/checkout@" in text and "persist-credentials: false" not in text:
        errors.append(f"{relative}: checkout credentials must not persist")
    references = ACTION_REF_RE.findall(text)
    if not references:
        errors.append(f"{relative}: expected at least one pinned GitHub Action")
    for reference in references:
        if not re.fullmatch(r"[0-9a-f]{40}", reference):
            errors.append(f"{relative}: action reference {reference!r} must be pinned to a 40-character commit SHA")
    return errors


def _read_text_cache(text_cache: dict[Path, str] | None, path: Path) -> str:
    if text_cache is None:
        return path.read_text(encoding="utf-8")
    if path not in text_cache:
        text_cache[path] = path.read_text(encoding="utf-8")
    return text_cache[path]


def validate_workflow_security(root: Path, text_cache: dict[Path, str] | None = None) -> list[str]:
    errors: list[str] = []
    for relative in WORKFLOW_PATHS:
        path = root / relative
        if not path.is_file():
            continue
        text = _read_text_cache(text_cache, path)
        if "pull_request_target:" in text or re.search(r"(?mi)^\s*permissions:\s*write-all\s*$", text):
            errors.append(f"{relative}: unsafe workflow trigger or write-all permission")
        if WRITE_PERMISSION_RE.search(text):
            errors.append(f"{relative}: workflow permissions must remain read-only")
        if "permissions:\n  contents: read" not in text:
            errors.append(f"{relative}: must declare top-level contents: read permissions")
        errors.extend(_validate_action_pins(relative, text))

    publish = root / PUBLISH_WORKFLOW
    if publish.is_file():
        text = _read_text_cache(text_cache, publish)
        if "pull_request:" in text or "pull_request_target:" in text:
            errors.append(f"{PUBLISH_WORKFLOW}: publisher must never run from pull-request events")
        if "permissions:\n  contents: write" not in text:
            errors.append(f"{PUBLISH_WORKFLOW}: publisher must declare only contents: write")
        unexpected_writes = [m.group(0) for m in WRITE_PERMISSION_RE.finditer(text) if "contents:" not in m.group(0).lower()]
        if unexpected_writes:
            errors.append(f"{PUBLISH_WORKFLOW}: publisher grants unexpected write permissions")
        errors.extend(_validate_action_pins(PUBLISH_WORKFLOW, text))
    return errors


def validate_required_content(root: Path, text_cache: dict[Path, str] | None = None) -> list[str]:
    errors = [f"Missing required file: {path}" for path in REQUIRED_FILES if not (root / path).is_file()]
    errors.extend(
        f"Forbidden upstream path on CamCore default branch: {path}"
        for path in FORBIDDEN_DEFAULT_BRANCH_PATHS if (root / path).exists()
    )
    phrase_checks = {
        "README.md": (
            CANONICAL_DESCRIPTION, "CamCore DNS Blocklist", "HaGeZi Multi NORMAL",
            "blocklist.txt", "upstream-hagezi", "minimal",
        ),
        "docs/UPSTREAM.md": (
            "hagezi/dns-blocklists", "GPL-3.0", "does not claim authorship",
            "upstream-hagezi", "must not be merged into `main`",
        ),
        "NOTICE.md": ("HaGeZi", "upstream-hagezi"),
    }
    for relative, phrases in phrase_checks.items():
        path = root / relative
        if path.is_file():
            text = _read_text_cache(text_cache, path)
            for phrase in phrases:
                if phrase not in text:
                    errors.append(f"{relative}: missing required phrase: {phrase!r}")
    licence = root / "LICENSE"
    if licence.is_file():
        text = _read_text_cache(text_cache, licence)
        if "GNU GENERAL PUBLIC LICENSE" not in text or "Version 3" not in text:
            errors.append("LICENSE: expected the GNU General Public License version 3")
    return errors


def repository_text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if (
            path.is_file()
            and ".git" not in path.parts
            and ".pytest_cache" not in path.parts
            and "__pycache__" not in path.parts
        ):
            if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE", "CODEOWNERS"}:
                yield path


def validate_text_and_secrets(root: Path, text_cache: dict[Path, str] | None = None) -> list[str]:
    errors: list[str] = []
    for path in repository_text_files(root):
        raw = path.read_bytes()
        try:
            if text_cache is not None and path in text_cache:
                text = text_cache[path]
            else:
                text = raw.decode("utf-8")
                if text_cache is not None:
                    text_cache[path] = text
        except UnicodeDecodeError:
            errors.append(f"{path}: text file is not valid UTF-8")
            continue
        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{path}: UTF-8 byte-order marks are not allowed")
        if b"\r" in raw:
            errors.append(f"{path}: CRLF or CR line endings are not allowed")
        if raw and not raw.endswith(b"\n"):
            errors.append(f"{path}: file must end with a newline")
        for number, line in enumerate(text.splitlines(), 1):
            if line.rstrip(" \t") != line:
                errors.append(f"{path}:{number}: trailing whitespace is not allowed")
        for pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                number = text.count("\n", 0, match.start()) + 1
                errors.append(f"{path}:{number}: possible secret or private-key material detected")
    return errors


def validate_repository(root: Path = REPO_ROOT) -> list[str]:
    text_cache: dict[Path, str] = {}
    errors = validate_required_content(root, text_cache)
    errors.extend(validate_manifest(root / "camcore/sources.json"))
    allow, allow_errors = read_domain_entries(root / "camcore/allowlist.txt")
    deny, deny_errors = read_domain_entries(root / "camcore/denylist.txt")
    errors.extend(allow_errors + deny_errors)
    for domain in sorted(set(allow) & set(deny)):
        errors.append(f"Domain appears in both allow-list and deny-list: {domain}")
    for domain in deny:
        if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in PROTECTED_SUFFIXES):
            errors.append(f"Protected namespace must not appear in local deny-list: {domain}")
    errors.extend(validate_workflow_security(root, text_cache))
    errors.extend(validate_text_and_secrets(root, text_cache))
    return errors


def pluralised(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def main() -> int:
    errors = validate_repository()
    if errors:
        print("CamCore DNS repository validation failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    allow, _ = read_domain_entries(REPO_ROOT / "camcore/allowlist.txt")
    deny, _ = read_domain_entries(REPO_ROOT / "camcore/denylist.txt")
    manifest = json.loads((REPO_ROOT / "camcore/sources.json").read_text(encoding="utf-8"))
    active = sum(
        source.get("status") == "active" and source.get("deployment") == "production"
        for source in manifest["sources"] if isinstance(source, dict)
    )
    print(
        "CamCore DNS repository validation passed: "
        f"{pluralised(active, 'production source')}, "
        f"{pluralised(len(allow), 'allow-list entry', 'allow-list entries')}, "
        f"{pluralised(len(deny), 'deny-list entry', 'deny-list entries')}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
