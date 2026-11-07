from pathlib import Path

from reposentry.models import Severity
from reposentry.scanner import scan_repository


def test_scanner_finds_static_source_workflow_and_dependency_signals(tmp_path: Path) -> None:
    (tmp_path / "demo.py").write_text("eval(user_input)\n", encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=example", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{"postinstall":"node setup.js"}}', encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows"
    workflow.mkdir(parents=True)
    (workflow / "release.yml").write_text("permissions: write-all\n- uses: acme/tool@main\n", encoding="utf-8")
    report = scan_repository(tmp_path)
    identifiers = {finding.rule_id for finding in report.findings}
    assert {"execution.dynamic-eval", "repository.sensitive-file", "dependency.lifecycle-script", "workflow.write-all", "workflow.unpinned-action"} <= identifiers
    assert any(finding.severity is Severity.WARNING for finding in report.findings)
