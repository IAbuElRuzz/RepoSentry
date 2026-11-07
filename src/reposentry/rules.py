"""Explainable static patterns. Matches are review signals, not conclusions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Rule:
    identifier: str
    severity: Severity
    title: str
    pattern: re.Pattern[str]
    recommendation: str


RULES = (
    Rule("secret.github-token", Severity.WARNING, "Possible GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "Remove and rotate the token; load credentials from a secret store."),
    Rule("secret.aws-access-key", Severity.WARNING, "Possible AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Remove and rotate the key; use environment-based credentials."),
    Rule("execution.download-pipe-shell", Severity.WARNING, "Remote content piped into a shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.IGNORECASE), "Review the downloaded source; prefer a pinned artifact with checksum verification."),
    Rule("execution.dynamic-eval", Severity.REVIEW, "Dynamic code evaluation", re.compile(r"\b(?:eval|exec)\s*\("), "Trace input to dynamic execution and remove it where practical."),
    Rule("execution.shell-true", Severity.REVIEW, "Shell command execution enabled", re.compile(r"\bshell\s*=\s*True\b"), "Avoid shell=True for untrusted input; pass an argument list instead."),
)

SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
SENSITIVE_FILE_NAMES = {".env", "id_rsa", "id_ed25519"}
MAX_FILE_BYTES = 1_000_000
LANGUAGE_BY_EXTENSION = {".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript", ".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".c": "C", ".cpp": "C++", ".md": "Markdown", ".yml": "YAML", ".yaml": "YAML"}
SOURCE_RULE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".zsh", ".go", ".rs", ".java", ".rb", ".php", ".cs", ".c", ".cpp"}
