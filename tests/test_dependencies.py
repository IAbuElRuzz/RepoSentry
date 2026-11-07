from reposentry.dependencies import online_dependency_findings


class FakeRegistry:
    def pypi(self, name: str):
        return None

    def npm(self, name: str):
        return {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"deprecated": "Use a replacement"}}}


def test_online_dependency_findings_report_resolvable_evidence() -> None:
    findings = online_dependency_findings(["not-a-real-package"], ["old-package"], FakeRegistry())
    assert {finding.rule_id for finding in findings} == {"dependency.pypi-unresolved", "dependency.npm-deprecated"}
