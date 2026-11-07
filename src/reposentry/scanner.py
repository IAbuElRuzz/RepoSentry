"""Bounded local inspection that never executes repository code or scripts."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .models import Finding, Report, RepositoryStats, Severity
from .dependencies import online_dependency_findings
from .registries import RegistryClient
from .rules import LANGUAGE_BY_EXTENSION, MAX_FILE_BYTES, RULES, SENSITIVE_FILE_NAMES, SKIPPED_DIRECTORIES, SOURCE_RULE_EXTENSIONS


def scan_repository(root: Path, online: bool = False, registry_client: RegistryClient | None = None) -> Report:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    findings: list[Finding] = []
    languages: Counter[str] = Counter()
    scanned = skipped = byte_count = 0
    python_dependencies: list[str] = []
    npm_dependencies: list[str] = []
    for path in _iter_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            skipped += 1
            continue
        if size > MAX_FILE_BYTES or _is_binary(path):
            skipped += 1
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        scanned += 1
        byte_count += size
        if language := LANGUAGE_BY_EXTENSION.get(path.suffix.lower()):
            languages[language] += 1
        findings.extend(_source_findings(relative, path.name, path.suffix.lower(), text))
        if path.name == "package.json":
            findings.extend(_package_json_findings(relative, text))
            npm_dependencies.extend(_npm_dependency_names(text))
        if path.name in {"requirements.txt", "Pipfile", "pyproject.toml"}:
            findings.extend(_python_dependency_findings(relative, text))
        if path.name == "requirements.txt":
            python_dependencies.extend(_requirement_names(text))
        findings.extend(_workflow_findings(relative, text))
    if online:
        findings.extend(online_dependency_findings(python_dependencies, npm_dependencies, registry_client or RegistryClient()))
    return Report(str(root), RepositoryStats(scanned, skipped, byte_count, dict(sorted(languages.items()))), tuple(findings))


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIPPED_DIRECTORIES for part in path.parts):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


def _is_binary(path: Path) -> bool:
    try:
        return b"\0" in path.read_bytes()[:4096]
    except OSError:
        return True


def _source_findings(path: str, file_name: str, extension: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if file_name in SENSITIVE_FILE_NAMES:
        findings.append(Finding("repository.sensitive-file", Severity.WARNING, "Potentially sensitive file committed", path, None, file_name, "Remove it from version control and rotate any exposed credentials."))
    if extension in SOURCE_RULE_EXTENSIONS:
        for number, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                if rule.pattern.search(line):
                    findings.append(Finding(rule.identifier, rule.severity, rule.title, path, number, line.strip()[:240], rule.recommendation))
    return findings


def _package_json_findings(path: str, text: str) -> list[Finding]:
    try:
        package = json.loads(text)
    except json.JSONDecodeError:
        return [Finding("dependency.invalid-package-json", Severity.REVIEW, "Invalid package.json", path, None, "JSON parsing failed.", "Fix the manifest before trusting dependency or script analysis.")]
    scripts = package.get("scripts", {})
    findings: list[Finding] = []
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if name in {"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}:
                findings.append(Finding("dependency.lifecycle-script", Severity.REVIEW, "npm lifecycle script present", path, None, f"{name}: {command}", "Review install-time commands before installing dependencies."))
    return findings


def _npm_dependency_names(text: str) -> list[str]:
    try:
        package = json.loads(text)
    except json.JSONDecodeError:
        return []
    names: list[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section, {})
        if isinstance(values, dict):
            names.extend(name for name, version in values.items() if isinstance(name, str) and isinstance(version, str) and not version.startswith(("file:", "git+", "http:" , "https:")))
    return names


def _python_dependency_findings(path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if value and not value.startswith("#") and ("git+" in value or "@ http" in value):
            findings.append(Finding("dependency.direct-url", Severity.REVIEW, "Direct URL or Git dependency", path, number, value[:240], "Review the source, pin a commit/hash, and record why this non-index dependency is required."))
    return findings


def _requirement_names(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        value = line.strip()
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)", value)
        if match and not value.startswith(("-", "#")):
            names.append(match.group(1))
    return names


def _workflow_findings(path: str, text: str) -> list[Finding]:
    if not path.startswith(".github/workflows/"):
        return []
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if value == "permissions: write-all":
            findings.append(Finding("workflow.write-all", Severity.WARNING, "Workflow grants write-all permissions", path, number, value, "Grant only the permissions each job needs."))
        if value.startswith("pull_request_target:"):
            findings.append(Finding("workflow.pull-request-target", Severity.REVIEW, "Workflow uses pull_request_target", path, number, value, "Review checkout and secret use carefully because this trigger has privileged context."))
        action_reference = value.removeprefix("- ")
        if action_reference.startswith("uses:") and "@" in action_reference and action_reference.rsplit("@", 1)[1] in {"main", "master", "latest"}:
            findings.append(Finding("workflow.unpinned-action", Severity.REVIEW, "GitHub Action is branch-pinned", path, number, value, "Pin third-party Actions to a full commit SHA."))
    return findings
