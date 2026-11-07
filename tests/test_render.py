from pathlib import Path

from reposentry.render import render_markdown
from reposentry.scanner import scan_repository


def test_report_explains_static_only_boundary(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Sample", encoding="utf-8")
    report = scan_repository(tmp_path)
    text = render_markdown(report)
    assert "never executes repository code" in text
    assert "not a malware verdict" in text
