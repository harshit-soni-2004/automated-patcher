from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from ami_patcher.exceptions import (
    ExceptionEntry,
    ExceptionsError,
    Finding,
    evaluate,
    load_exceptions,
)

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 12)


def _entry(**overrides: object) -> ExceptionEntry:
    values: dict[str, object] = {
        "cve": "CVE-2024-24790",
        "target": "opt/aws/bin/eic_run_authorized_keys",
        "component": "ec2-instance-connect",
        "reason": "vendor binary",
        "approved_by": "security-owner",
        "added": date(2026, 10, 12),
        "review_by": date(2026, 11, 12),
        "severity": "CRITICAL",
    }
    values.update(overrides)
    return ExceptionEntry(**values)  # type: ignore[arg-type]


def test_shipped_exceptions_cover_known_vendor_findings_and_refuse_os_packages() -> None:
    entries = load_exceptions(ROOT / "exceptions.yaml")
    findings = [
        Finding("CVE-2024-24790", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False),
        Finding("CVE-2025-68121", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False),
        Finding("CVE-2024-24790", "/opt/aws/inspector/bin/inspectorssmplugin", "stdlib", "CRITICAL", False),
        Finding("CVE-2025-68121", "opt/aws/inspector/bin/inspectorssmplugin", "stdlib", "CRITICAL", False),
        Finding("CVE-2026-1000", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "HIGH", False),
        Finding("CVE-2026-2000", "opt/aws/inspector/bin/inspectorssmplugin", "stdlib", "HIGH", False),
        Finding(
            "CVE-2026-3000",
            "var/lib/amazon/ssm/update/amazon-ssm-agent-updater/3.3.5390.0/updater",
            "stdlib",
            "HIGH",
            False,
        ),
        Finding("CVE-2024-1111", "localhost (alma 9.8)", "kernel", "HIGH", True),
        Finding("CVE-2099-1", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False),
    ]
    result = evaluate(entries, findings, today=TODAY)
    assert result.passed is False
    assert [finding.vulnerability_id for finding in result.os_uncovered] == ["CVE-2024-1111"]
    uncovered_ids = {finding.vulnerability_id for finding in result.uncovered}
    assert uncovered_ids == {"CVE-2024-1111", "CVE-2099-1"}
    assert len(result.covered) == 7
    assert result.warnings == ()


def test_wildcard_does_not_cover_critical_and_review_by_is_inclusive() -> None:
    wildcard = _entry(cve="*", severity="HIGH", review_by=TODAY)
    critical = Finding("CVE-2099-1", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False)
    high = Finding("CVE-2099-2", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "HIGH", False)
    result = evaluate([wildcard], [critical, high], today=TODAY)
    assert [finding.vulnerability_id for finding in result.uncovered] == ["CVE-2099-1"]
    assert [finding.vulnerability_id for finding in result.covered] == ["CVE-2099-2"]


def test_expired_exception_does_not_cover_and_warns() -> None:
    expired = _entry(review_by=date(2026, 10, 11))
    finding = Finding("CVE-2024-24790", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False)
    result = evaluate([expired], [finding], today=TODAY)
    assert result.uncovered == (finding,)
    assert [warning.code for warning in result.warnings] == ["expired"]


def test_stale_exception_warns_without_failing_a_clean_set() -> None:
    used = _entry()
    unused = _entry(cve="CVE-2020-0001", target="opt/aws/bin/somewhere-else")
    finding = Finding("CVE-2024-24790", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "CRITICAL", False)
    result = evaluate([used, unused], [finding], today=TODAY)
    assert result.passed is True
    assert [warning.code for warning in result.warnings] == ["stale"]


def test_new_cve_under_a_wildcard_warns_and_still_covers() -> None:
    wildcard = _entry(cve="*", severity="HIGH")
    finding = Finding("CVE-2026-9999", "opt/aws/bin/eic_run_authorized_keys", "stdlib", "HIGH", False)
    first = evaluate([wildcard], [finding], today=TODAY, previous_cve_ids=set())
    assert first.passed is True
    assert [warning.code for warning in first.warnings] == ["new_wildcard_cve"]
    again = evaluate([wildcard], [finding], today=TODAY, previous_cve_ids={"CVE-2026-9999"})
    assert again.warnings == ()


def test_os_package_cannot_be_excepted_even_with_a_broad_target() -> None:
    broad = _entry(cve="*", severity="HIGH", target="localhost*")
    finding = Finding("CVE-2024-1111", "localhost (alma 9.8)", "kernel", "HIGH", True)
    result = evaluate([broad], [finding], today=TODAY)
    assert result.uncovered == (finding,)
    assert result.warnings[0].code == "os_package_cannot_be_excepted"


def test_rejects_global_wildcard_critical_wildcard_and_bad_dates(tmp_path: Path) -> None:
    path = tmp_path / "exceptions.yaml"
    path.write_text(
        """
        exceptions:
          - cve: "*"
            severity: CRITICAL
            target: "*"
            component: everywhere
            reason: too broad
            approved_by: security-owner
            added: 2026-10-12
            review_by: 2026-10-01
        """,
        encoding="utf-8",
    )
    with pytest.raises(ExceptionsError) as caught:
        load_exceptions(path)
    text = str(caught.value)
    assert "severity LOW, MEDIUM, or HIGH" in text
    assert "global wildcard" in text
    assert "review_by is earlier than added" in text
