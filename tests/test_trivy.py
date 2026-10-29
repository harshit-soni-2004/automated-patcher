from __future__ import annotations

from pathlib import Path

import pytest

from ami_patcher.trivy import TrivyParseError, load_scan, parse_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_before_scan_counts_rows_separately_from_distinct_cves() -> None:
    summary = load_scan(FIXTURES / "trivy_before.json")
    assert summary.total_rows == 7
    assert summary.distinct_cves == 4
    assert summary.os_rows == 4
    assert summary.non_os_rows == 3
    assert summary.per_target["localhost (alma 9.8)"] == 4
    assert summary.per_package["kernel"] == 2
    assert summary.per_package["kernel-core"] == 2
    assert summary.per_target_package["localhost (alma 9.8)"]["kernel"] == 2
    assert summary.rows_by_severity == {"HIGH": 4, "CRITICAL": 3}
    # CVE-2024-2222 is HIGH in one package and CRITICAL in another, so its distinct severity is CRITICAL.
    assert summary.distinct_cves_by_severity["CRITICAL"] == 2
    assert summary.distinct_cves_by_severity["HIGH"] == 2
    assert summary.rows[0].is_os_package is True
    assert summary.rows[-1].is_os_package is False
    assert summary.rows[0].fixed_version == "5.14.0-687.54.1.el9_8"


def test_after_scan_has_no_os_rows() -> None:
    summary = load_scan(FIXTURES / "trivy_after.json")
    assert summary.os_rows == 0
    assert summary.total_rows == 7
    assert summary.distinct_cves == 5
    assert summary.per_target["opt/aws/bin/eic_run_authorized_keys"] == 3
    assert summary.per_target["var/lib/amazon/ssm/update/amazon-ssm-agent-updater/3.3.5390.0/updater"] == 1


def test_null_vulnerabilities_are_empty_and_secrets_are_separate() -> None:
    summary = load_scan(FIXTURES / "trivy_null_and_secrets.json")
    assert summary.total_rows == 0
    assert summary.distinct_cves == 0
    assert len(summary.secrets) == 3
    assert summary.secrets[0].target == "etc/ssh/ssh_host_ed25519_key"
    assert summary.secrets[0].severity == "HIGH"
    assert summary.to_dict()["secret_count"] == 3


def test_missing_results_is_an_empty_scan() -> None:
    summary = parse_scan({"SchemaVersion": 2})
    assert summary.total_rows == 0
    summary = parse_scan({"Results": None})
    assert summary.total_rows == 0


def test_malformed_report_fails_loudly() -> None:
    with pytest.raises(TrivyParseError, match="JSON object"):
        parse_scan([])
    with pytest.raises(TrivyParseError, match="Results must be a list"):
        parse_scan({"Results": {}})
    with pytest.raises(TrivyParseError, match="Vulnerabilities must be a list"):
        parse_scan({"Results": [{"Vulnerabilities": {}}]})
    with pytest.raises(TrivyParseError, match="VulnerabilityID"):
        parse_scan({"Results": [{"Class": "os-pkgs", "Type": "alma", "Vulnerabilities": [{"PkgName": "kernel"}]}]})
