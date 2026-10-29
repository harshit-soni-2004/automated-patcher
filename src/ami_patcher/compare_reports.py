"""Compare baseline and post-patch Trivy reports by finding identity, not by count."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ami_patcher.trivy import ScanSummary, load_scan

_MATCH_NOTE = (
    "Findings are matched on vulnerability id, package name, and target. "
    "Installed version is not part of the match. A lower row count is not by itself a fix."
)


def _raw_key(row) -> tuple[str, str, str]:
    return (row.vulnerability_id, row.pkg_name, row.target)


def _summary_key(item: dict) -> tuple[str, str, str]:
    return (
        str(item.get("vulnerability_id") or ""),
        str(item.get("pkg_name") or ""),
        str(item.get("target") or ""),
    )


def _counts(scan: ScanSummary) -> dict:
    return {
        "rows_by_severity": scan.rows_by_severity,
        "distinct_cves": scan.distinct_cves,
        "distinct_cves_by_severity": scan.distinct_cves_by_severity,
        "total_rows": scan.total_rows,
    }


def compare_scans(
    *,
    baseline: ScanSummary,
    post: ScanSummary,
    baseline_summary: dict,
    post_summary: dict,
    run_id: str,
    baseline_report_prefix: str,
    post_report_prefix: str,
) -> dict:
    baseline_coverage = str(baseline_summary.get("scan_coverage") or "")
    post_coverage = str(post_summary.get("scan_coverage") or "")
    coverage_matches = bool(baseline_coverage) and baseline_coverage == post_coverage
    baseline_raw = {_raw_key(row) for row in baseline.rows}
    post_raw = {_raw_key(row) for row in post.rows}
    baseline_unresolved = {_summary_key(item) for item in baseline_summary.get("unresolved_findings") or []}
    post_unresolved = {_summary_key(item) for item in post_summary.get("unresolved_findings") or []}
    limitation = None
    if not coverage_matches:
        limitation = (
            "Baseline coverage "
            f"{baseline_coverage or 'unknown'} differs from post-patch coverage "
            f"{post_coverage or 'unknown'}. Resolved, remaining, and new counts are not a direct comparison."
        )
    return {
        "run_id": run_id,
        "comparison_valid": coverage_matches,
        "matching_limitation": limitation,
        "match_note": _MATCH_NOTE,
        "baseline": {
            "scan_coverage": baseline_coverage,
            "scanned_at": baseline_summary.get("scanned_at"),
            "report_prefix": baseline_report_prefix,
            **_counts(baseline),
            "accepted_rows": len(baseline_summary.get("accepted_exceptions") or []),
            "unresolved_rows": len(baseline_unresolved),
        },
        "post_patch": {
            "scan_coverage": post_coverage,
            "scanned_at": post_summary.get("scanned_at"),
            "report_prefix": post_report_prefix,
            **_counts(post),
            "accepted_rows": len(post_summary.get("accepted_exceptions") or []),
            "unresolved_rows": len(post_unresolved),
        },
        "raw": {
            "resolved": len(baseline_raw - post_raw),
            "remaining": len(baseline_raw & post_raw),
            "new": len(post_raw - baseline_raw),
        },
        "unresolved": {
            "resolved": len(baseline_unresolved - post_unresolved),
            "remaining": len(baseline_unresolved & post_unresolved),
            "new": len(post_unresolved - baseline_unresolved),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write comparison.json from the two Trivy scans.")
    parser.add_argument("--baseline-scan", type=Path, required=True)
    parser.add_argument("--post-scan", type=Path, required=True)
    parser.add_argument("--baseline-summary", type=Path, required=True)
    parser.add_argument("--post-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--baseline-prefix", required=True)
    parser.add_argument("--post-prefix", required=True)
    args = parser.parse_args(argv)
    document = compare_scans(
        baseline=load_scan(args.baseline_scan),
        post=load_scan(args.post_scan),
        baseline_summary=json.loads(args.baseline_summary.read_text(encoding="utf-8")),
        post_summary=json.loads(args.post_summary.read_text(encoding="utf-8")),
        run_id=args.run_id,
        baseline_report_prefix=args.baseline_prefix,
        post_report_prefix=args.post_prefix,
    )
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "stage": "comparison",
                "comparison_valid": document["comparison_valid"],
                "raw_resolved": document["raw"]["resolved"],
                "raw_remaining": document["raw"]["remaining"],
                "raw_new": document["raw"]["new"],
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
