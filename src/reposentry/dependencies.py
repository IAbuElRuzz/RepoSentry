"""Dependency metadata review, deliberately framed as evidence not reputation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Finding, Severity
from .registries import RegistryClient, RegistryLookupError


def online_dependency_findings(python_names: Iterable[str], npm_names: Iterable[str], client: RegistryClient) -> list[Finding]:
    findings: list[Finding] = []
    for name in sorted(set(python_names)):
        findings.extend(_pypi_findings(name, client))
    for name in sorted(set(npm_names)):
        findings.extend(_npm_findings(name, client))
    return findings


def _pypi_findings(name: str, client: RegistryClient) -> list[Finding]:
    try:
        payload = client.pypi(name)
    except RegistryLookupError as error:
        return [Finding("dependency.registry-unavailable", Severity.INFO, "PyPI lookup unavailable", "requirements.txt", None, name, str(error))]
    if payload is None:
        return [Finding("dependency.pypi-unresolved", Severity.WARNING, "Python dependency does not resolve on PyPI", "requirements.txt", None, name, "Verify spelling and source before installation; it may be private or misspelled.")]
    info: dict[str, Any] = payload.get("info", {})
    if info.get("yanked"):
        return [Finding("dependency.pypi-yanked", Severity.WARNING, "Python dependency latest release is yanked", "requirements.txt", None, name, "Pin a supported version after reviewing why the release was yanked.")]
    return []


def _npm_findings(name: str, client: RegistryClient) -> list[Finding]:
    try:
        payload = client.npm(name)
    except RegistryLookupError as error:
        return [Finding("dependency.registry-unavailable", Severity.INFO, "npm lookup unavailable", "package.json", None, name, str(error))]
    if payload is None:
        return [Finding("dependency.npm-unresolved", Severity.WARNING, "npm dependency does not resolve", "package.json", None, name, "Verify spelling and source before installation; it may be private or misspelled.")]
    latest = (payload.get("dist-tags") or {}).get("latest")
    version = (payload.get("versions") or {}).get(latest, {})
    if isinstance(version, dict) and version.get("deprecated"):
        return [Finding("dependency.npm-deprecated", Severity.REVIEW, "npm dependency is deprecated", "package.json", None, f"{name}@{latest}: {version['deprecated']}", "Review the maintainer notice and migrate or pin deliberately.")]
    return []
