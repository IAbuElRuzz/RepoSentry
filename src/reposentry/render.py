from __future__ import annotations

import json

from .models import Report, Severity


def render_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2) + "\n"


def render_markdown(report: Report) -> str:
    stats = report.stats
    lines = ["# RepoSentry scan report", "", f"**Path:** `{report.root}`  ", f"**Files scanned:** {stats.files_scanned} · **Skipped:** {stats.files_skipped} · **Bytes read:** {stats.bytes_scanned}", "", "> RepoSentry performs static inspection only: it never executes repository code. Findings are review signals, not a malware verdict or an assessment of repository authors.", "", "## Languages", "", ", ".join(f"{language}: {count}" for language, count in stats.languages.items()) or "No recognized source-file extensions found.", ""]
    for severity in (Severity.WARNING, Severity.REVIEW, Severity.INFO):
        findings = [finding for finding in report.findings if finding.severity is severity]
        if findings:
            lines.extend([f"## {severity.value.title()} signals", ""])
            for finding in findings:
                location = f"`{finding.path}`" + (f":{finding.line}" if finding.line else "")
                lines.extend([f"- **{finding.title}** — {location}", f"  Evidence: `{finding.evidence}`", f"  Recommendation: {finding.recommendation}"])
            lines.append("")
    if not report.findings:
        lines.extend(["## Findings", "", "No current rules matched. This does not establish that the repository is safe.", ""])
    return "\n".join(lines).rstrip() + "\n"
