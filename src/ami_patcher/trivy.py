"""Parse Trivy JSON and count rows separately from distinct CVEs.

Trivy repeats one CVE for every package and every file. Row counts and CVE
counts are both kept so a report cannot present rows as vulnerabilities.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_OS_TYPES = {
    "alma",
    "redhat",
    "rhel",
    "oracle",
    "centos",
    "rocky",
    "fedora",
    "amzn",
    "amazon",
    "debian",
    "ubuntu",
    "alpine",
    "suse",
    "opensuse",
    "opensuse.leap",
    "photon",
    "cbl-mariner",
    "azurelinux",
}
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "UNKNOWN": 5}


class TrivyParseError(Exception):
    pass


@dataclass(frozen=True)
class VulnRow:
    vulnerability_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    status: str
    target: str
    result_class: str
    result_type: str

    @property
    def is_os_package(self) -> bool:
        return is_os_result(self.result_class, self.result_type)


@dataclass(frozen=True)
class SecretFinding:
    target: str
    rule_id: str
    severity: str
    title: str


@dataclass(frozen=True)
class ScanSummary:
    rows: tuple[VulnRow, ...]
    secrets: tuple[SecretFinding, ...]

    @property
    def total_rows(self) -> int:
        return len(self.rows)

    @property
    def distinct_cve_ids(self) -> frozenset[str]:
        return frozenset(row.vulnerability_id for row in self.rows)

    @property
    def distinct_cves(self) -> int:
        return len(self.distinct_cve_ids)

    @property
    def per_target(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for row in self.rows:
            counts[row.target] += 1
        return dict(counts)

    @property
    def per_package(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for row in self.rows:
            counts[row.pkg_name] += 1
        return dict(counts)

    @property
    def per_target_package(self) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for row in self.rows:
            counts[row.target][row.pkg_name] += 1
        return {target: dict(packages) for target, packages in counts.items()}

    @property
    def rows_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for row in self.rows:
            counts[row.severity] += 1
        return dict(counts)

    @property
    def distinct_cves_by_severity(self) -> dict[str, int]:
        worst: dict[str, str] = {}
        for row in self.rows:
            current = worst.get(row.vulnerability_id)
            if current is None or _SEVERITY_RANK.get(row.severity, 5) > _SEVERITY_RANK.get(current, 5):
                worst[row.vulnerability_id] = row.severity
        counts: dict[str, int] = defaultdict(int)
        for severity in worst.values():
            counts[severity] += 1
        return dict(counts)

    @property
    def os_rows(self) -> int:
        return sum(1 for row in self.rows if row.is_os_package)

    @property
    def non_os_rows(self) -> int:
        return self.total_rows - self.os_rows

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "distinct_cves": self.distinct_cves,
            "rows_by_severity": self.rows_by_severity,
            "distinct_cves_by_severity": self.distinct_cves_by_severity,
            "os_rows": self.os_rows,
            "non_os_rows": self.non_os_rows,
            "per_target": self.per_target,
            "per_package": self.per_package,
            "per_target_package": self.per_target_package,
            "secret_count": len(self.secrets),
        }


def load_scan(path: Path) -> ScanSummary:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TrivyParseError(f"Trivy report is not valid JSON: {exc}") from exc
    return parse_scan(document)


def parse_scan(document: Any) -> ScanSummary:
    if not isinstance(document, dict):
        raise TrivyParseError("Trivy report must be a JSON object")
    results = document.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise TrivyParseError("Results must be a list")
    rows: list[VulnRow] = []
    secrets: list[SecretFinding] = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise TrivyParseError(f"Results[{index}] must be an object")
        target = str(result.get("Target") or "")
        result_class = str(result.get("Class") or "")
        result_type = str(result.get("Type") or "")
        if result_class == "secret" or "Secrets" in result:
            secrets.extend(_parse_secret_result(result, index, target))
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise TrivyParseError(f"Results[{index}].Vulnerabilities must be a list or null")
        for vuln_index, vuln in enumerate(vulnerabilities):
            rows.append(
                _parse_vuln(vuln, f"Results[{index}].Vulnerabilities[{vuln_index}]", target, result_class, result_type)
            )
    return ScanSummary(rows=tuple(rows), secrets=tuple(secrets))


def is_os_result(result_class: str, result_type: str) -> bool:
    if result_class:
        return result_class == "os-pkgs"
    return result_type.lower() in _OS_TYPES


def _parse_vuln(vuln: Any, label: str, target: str, result_class: str, result_type: str) -> VulnRow:
    if not isinstance(vuln, dict):
        raise TrivyParseError(f"{label} must be an object")
    vulnerability_id = vuln.get("VulnerabilityID")
    if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
        raise TrivyParseError(f"{label} is missing VulnerabilityID")
    severity = vuln.get("Severity")
    if not isinstance(severity, str) or not severity.strip():
        severity = "UNKNOWN"
    return VulnRow(
        vulnerability_id=vulnerability_id.strip(),
        pkg_name=_text(vuln.get("PkgName")) or "(unknown)",
        installed_version=_text(vuln.get("InstalledVersion")),
        fixed_version=_text(vuln.get("FixedVersion")),
        severity=severity.strip().upper(),
        status=_text(vuln.get("Status")),
        target=target,
        result_class=result_class,
        result_type=result_type,
    )


def _parse_secret_result(result: dict, index: int, target: str) -> list[SecretFinding]:
    raw_secrets = result.get("Secrets")
    if raw_secrets is None:
        return []
    if not isinstance(raw_secrets, list):
        raise TrivyParseError(f"Results[{index}].Secrets must be a list")
    findings: list[SecretFinding] = []
    for secret_index, secret in enumerate(raw_secrets):
        if not isinstance(secret, dict):
            raise TrivyParseError(f"Results[{index}].Secrets[{secret_index}] must be an object")
        severity = secret.get("Severity")
        if not isinstance(severity, str) or not severity.strip():
            severity = "UNKNOWN"
        findings.append(
            SecretFinding(
                target=target,
                rule_id=_text(secret.get("RuleID")),
                severity=severity.strip().upper(),
                title=_text(secret.get("Title")),
            )
        )
    return findings


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
