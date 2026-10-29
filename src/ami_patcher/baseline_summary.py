"""Build summary.json on the EC2 instance from the Trivy files created there.

The orchestrator does not download those files. This module is copied to the
instance and executed there so accepted exceptions are not rewritten into a
local report.
"""

from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timezone
from pathlib import Path

from ami_patcher.exceptions import Finding, evaluate, load_exceptions
from ami_patcher.redact import redact
from ami_patcher.trivy import load_scan

VULN_SCAN = [
    "trivy",
    "rootfs",
    "/",
    "--scanners",
    "vuln",
    "--severity",
    "HIGH,CRITICAL",
    "--skip-dirs",
    "/proc,/sys,/dev,/run",
    "--skip-files",
    "/usr/bin/trivy",
]
SECRET_SCAN = [
    "trivy",
    "rootfs",
    "/",
    "--scanners",
    "secret",
    "--severity",
    "HIGH,CRITICAL",
    "--skip-dirs",
    "/proc,/sys,/dev,/run",
]


def write_summary(
    *,
    scan_path: Path,
    secrets_path: Path | None,
    exceptions_path: Path,
    output_path: Path,
    run_id: str,
    source_ami_id: str,
    instance_id: str,
    trivy_version: str,
    scan_exit_status: int,
    secret_scan_exit_status: int,
    upload_exit_status: int,
    scan_coverage: str = "full",
    today: date | None = None,
) -> dict:
    if scan_coverage not in {"full", "os-only"}:
        raise ValueError("scan_coverage must be full or os-only")
    package_types = "os" if scan_coverage == "os-only" else "os,library"
    scan = load_scan(scan_path)
    secrets = load_scan(secrets_path).secrets if secrets_path and secrets_path.is_file() else ()
    findings = [
        Finding(
            row.vulnerability_id,
            row.target,
            row.pkg_name,
            row.severity,
            row.is_os_package,
            row.installed_version,
        )
        for row in scan.rows
    ]
    gate = evaluate(load_exceptions(exceptions_path), findings, today=today or date.today())
    detected = scan.to_dict()
    detected["secret_count"] = len(secrets)
    document = {
        "run_id": run_id,
        "scanned_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_ami_id": source_ami_id,
        "instance_id": instance_id,
        "trivy_version": trivy_version,
        "scan_configuration": {
            "vulnerabilities": VULN_SCAN + ["--pkg-types", package_types],
            "secrets": SECRET_SCAN,
            "package_types": package_types,
        },
        "scan_coverage": scan_coverage,
        "detected": detected,
        "accepted_exceptions": [_finding(row) for row in gate.covered],
        "unresolved_findings": [_finding(row) for row in gate.uncovered],
        "exception_warnings": [
            {"code": warning.code, "message": warning.message, "cve": warning.cve, "target": warning.target}
            for warning in gate.warnings
        ],
        "secret_findings": [
            {
                "target": item.target,
                "rule_id": item.rule_id,
                "severity": item.severity,
                "title": redact(item.title),
            }
            for item in secrets
        ],
        "scan_exit_status": scan_exit_status,
        "secret_scan_exit_status": secret_scan_exit_status,
        "upload_exit_status": upload_exit_status,
        "note": (
            "Partial OS-only scan. Java and other library packages were not scanned because the Java vulnerability database did not fit on disk. Accepted exceptions are not remediated findings."
            if scan_coverage == "os-only"
            else "Accepted exceptions are not remediated findings."
        ),
    }
    output_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return {
        "stage": "baseline",
        "scan_exit": scan_exit_status,
        "secret_exit": secret_scan_exit_status,
        "upload_exit": upload_exit_status,
        "detected_rows": detected["total_rows"],
        "distinct_cves": detected["distinct_cves"],
        "accepted_rows": len(gate.covered),
        "unresolved_rows": len(gate.uncovered),
        "secret_count": len(secrets),
        "scan_coverage": scan_coverage,
    }


def _finding(finding: Finding) -> dict[str, str | bool]:
    return {
        "vulnerability_id": finding.vulnerability_id,
        "target": finding.target,
        "pkg_name": finding.pkg_name,
        "severity": finding.severity,
        "installed_version": finding.installed_version,
        "is_os_package": finding.is_os_package,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the on-instance Trivy summary.")
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--secrets", type=Path, required=True)
    parser.add_argument("--exceptions", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-ami", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--trivy-version-file", type=Path, required=True)
    parser.add_argument("--scan-exit", type=int, required=True)
    parser.add_argument("--secret-exit", type=int, required=True)
    parser.add_argument("--upload-exit", type=int, required=True)
    parser.add_argument("--scan-coverage", default="full")
    parser.add_argument("--today", default="")
    args = parser.parse_args(argv)
    version = args.trivy_version_file.read_text(encoding="utf-8").strip() if args.trivy_version_file.is_file() else ""
    today = date.fromisoformat(args.today) if args.today else None
    status = write_summary(
        scan_path=args.scan,
        secrets_path=args.secrets,
        exceptions_path=args.exceptions,
        output_path=args.output,
        run_id=args.run_id,
        source_ami_id=args.source_ami,
        instance_id=args.instance_id,
        trivy_version=version,
        scan_exit_status=args.scan_exit,
        secret_scan_exit_status=args.secret_exit,
        upload_exit_status=args.upload_exit,
        scan_coverage=args.scan_coverage,
        today=today,
    )
    print(json.dumps(status), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
