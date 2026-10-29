"""Exception list for non-OS findings that AWS has not shipped a fix for.

An OS-package finding can never be covered. A wildcard covers one non-OS target
up to the stated severity and nothing above it. An explicit CVE id covers that
CVE on the target at whatever severity the scanner reports. An entry remains
valid through its review_by date.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_WILDCARD_SEVERITIES = {"LOW", "MEDIUM", "HIGH"}


class ExceptionsError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class ExceptionEntry:
    cve: str
    target: str
    component: str
    reason: str
    approved_by: str
    added: date
    review_by: date
    severity: str | None = None

    @property
    def is_wildcard(self) -> bool:
        return self.cve == "*"


@dataclass(frozen=True)
class Finding:
    vulnerability_id: str
    target: str
    pkg_name: str
    severity: str
    is_os_package: bool
    installed_version: str = ""


@dataclass(frozen=True)
class GateWarning:
    code: str
    message: str
    cve: str | None = None
    target: str | None = None


@dataclass(frozen=True)
class GateResult:
    covered: tuple[Finding, ...]
    uncovered: tuple[Finding, ...]
    warnings: tuple[GateWarning, ...]

    @property
    def passed(self) -> bool:
        return not self.uncovered

    @property
    def os_uncovered(self) -> tuple[Finding, ...]:
        return tuple(finding for finding in self.uncovered if finding.is_os_package)


def load_exceptions(path: Path) -> list[ExceptionEntry]:
    if not path.is_file():
        raise ExceptionsError([f"exceptions file not found: {path}"])
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ExceptionsError([f"exceptions file is not valid YAML: {exc}"]) from exc
    if not isinstance(loaded, dict) or not isinstance(loaded.get("exceptions"), list):
        raise ExceptionsError(["exceptions file must contain an exceptions list"])
    entries: list[ExceptionEntry] = []
    errors: list[str] = []
    for index, raw in enumerate(loaded["exceptions"], start=1):
        entry = _parse_entry(raw, index, errors)
        if entry is not None:
            entries.append(entry)
    if errors:
        raise ExceptionsError(errors)
    return entries


def evaluate(
    entries: list[ExceptionEntry],
    findings: list[Finding],
    *,
    today: date,
    previous_cve_ids: set[str] | None = None,
) -> GateResult:
    """Decide which findings are covered. Warnings never hide an uncovered finding."""
    covered: list[Finding] = []
    uncovered: list[Finding] = []
    warnings: list[GateWarning] = []
    matched_entry_indexes: set[int] = set()
    warned_new: set[str] = set()
    warned_os: set[tuple[str, str]] = set()

    for entry in entries:
        if entry.review_by < today:
            warnings.append(
                GateWarning(
                    code="expired",
                    message=f"exception for {entry.cve} on {entry.target} was due for review on {entry.review_by.isoformat()}",
                    cve=entry.cve,
                    target=entry.target,
                )
            )

    for finding in findings:
        effective = [
            (index, entry)
            for index, entry in enumerate(entries)
            if _matches(entry, finding) and entry.review_by >= today
        ]
        if finding.is_os_package:
            uncovered.append(finding)
            for entry in entries:
                if _matches(entry, finding, ignore_os=True):
                    key = (entry.cve, entry.target)
                    if key not in warned_os:
                        warned_os.add(key)
                        warnings.append(
                            GateWarning(
                                code="os_package_cannot_be_excepted",
                                message=f"exception {entry.cve} on {entry.target} cannot cover OS package {finding.pkg_name}",
                                cve=finding.vulnerability_id,
                                target=finding.target,
                            )
                        )
            continue
        if not effective:
            uncovered.append(finding)
            continue
        covered.append(finding)
        matched_entry_indexes.update(index for index, _entry in effective)
        wildcard_cover = [entry for _index, entry in effective if entry.is_wildcard]
        if (
            previous_cve_ids is not None
            and wildcard_cover
            and finding.vulnerability_id not in previous_cve_ids
            and finding.vulnerability_id not in warned_new
        ):
            warned_new.add(finding.vulnerability_id)
            warnings.append(
                GateWarning(
                    code="new_wildcard_cve",
                    message=f"{finding.vulnerability_id} is new under wildcard {wildcard_cover[0].target}",
                    cve=finding.vulnerability_id,
                    target=finding.target,
                )
            )

    for index, entry in enumerate(entries):
        if entry.review_by >= today and index not in matched_entry_indexes:
            warnings.append(
                GateWarning(
                    code="stale",
                    message=f"exception for {entry.cve} on {entry.target} matched no current finding",
                    cve=entry.cve,
                    target=entry.target,
                )
            )
    return GateResult(covered=tuple(covered), uncovered=tuple(uncovered), warnings=tuple(warnings))


def _parse_entry(raw: Any, index: int, errors: list[str]) -> ExceptionEntry | None:
    label = f"exceptions[{index}]"
    if not isinstance(raw, dict):
        errors.append(f"{label} must be a mapping")
        return None
    cve = raw.get("cve")
    target = raw.get("target")
    severity = raw.get("severity")
    if cve == "*":
        if not isinstance(severity, str) or severity.upper() not in _WILDCARD_SEVERITIES:
            errors.append(f"{label} wildcard requires severity LOW, MEDIUM, or HIGH")
            severity_value = None
        else:
            severity_value = severity.upper()
    elif isinstance(cve, str) and _CVE_ID.match(cve):
        if severity is None:
            severity_value = None
        elif isinstance(severity, str) and severity.upper() in _SEVERITY_RANK:
            severity_value = severity.upper()
        else:
            errors.append(f"{label} severity must be LOW, MEDIUM, HIGH, or CRITICAL")
            severity_value = None
    else:
        errors.append(f"{label} cve must be an explicit CVE id or *")
        severity_value = None
    if not isinstance(target, str) or not target.strip():
        errors.append(f"{label} target is required")
        target_value = ""
    else:
        target_value = _normalize_target(target)
        if target_value in {"*", "**"} or target_value.startswith("*"):
            errors.append(f"{label} target must be a path glob, not a global wildcard")
            target_value = ""
    component = _required_text(raw, "component", label, errors)
    reason = _required_text(raw, "reason", label, errors)
    approved_by = _required_text(raw, "approved_by", label, errors)
    added = _required_date(raw, "added", label, errors)
    review_by = _required_date(raw, "review_by", label, errors)
    if added is not None and review_by is not None and review_by < added:
        errors.append(f"{label} review_by is earlier than added")
    if (
        not isinstance(cve, str)
        or not target_value
        or component is None
        or reason is None
        or approved_by is None
        or added is None
        or review_by is None
        or (cve == "*" and severity_value is None)
    ):
        return None
    return ExceptionEntry(
        cve=cve,
        target=target_value,
        component=component,
        reason=reason,
        approved_by=approved_by,
        added=added,
        review_by=review_by,
        severity=severity_value,
    )


def _matches(entry: ExceptionEntry, finding: Finding, *, ignore_os: bool = False) -> bool:
    if finding.is_os_package and not ignore_os:
        return False
    if not fnmatch.fnmatchcase(_normalize_target(finding.target), entry.target):
        return False
    if entry.is_wildcard:
        return _SEVERITY_RANK.get(finding.severity.upper(), 5) <= _SEVERITY_RANK[entry.severity or "HIGH"]
    return entry.cve == finding.vulnerability_id


def _normalize_target(target: str) -> str:
    text = target.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _required_text(raw: dict, key: str, label: str, errors: list[str]) -> str | None:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label} {key} is required")
        return None
    return value.strip()


def _required_date(raw: dict, key: str, label: str, errors: list[str]) -> date | None:
    value = raw.get(key)
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            errors.append(f"{label} {key} must be YYYY-MM-DD")
            return None
    errors.append(f"{label} {key} must be YYYY-MM-DD")
    return None
