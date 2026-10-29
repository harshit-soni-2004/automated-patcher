"""Build the patch-stage report on the instance that ran the package update."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def read_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return {
        "id": values.get("ID", ""),
        "version_id": values.get("VERSION_ID", ""),
        "pretty_name": values.get("PRETTY_NAME", ""),
    }


def updates_applied(log_text: str, package_manager: str) -> bool | None:
    if package_manager == "apt-get":
        match = re.search(r"(\d+) upgraded", log_text)
        if match:
            return int(match.group(1)) > 0
        return None
    if "Nothing to do" in log_text:
        return False
    if re.search(r"^Upgraded:", log_text, re.MULTILINE):
        return True
    return None


def upgrade_summary(log_text: str, limit: int = 30) -> str:
    lines = [line for line in log_text.splitlines() if line.strip()]
    return "\n".join(lines[-limit:])


def build_patch_report(
    *,
    run_id: str,
    instance_id: str,
    os_release_text: str,
    package_manager: str,
    started_at: str,
    ended_at: str,
    exit_status: int,
    reboot_required: bool,
    reboot_check: str,
    log_text: str,
    warnings: list[str] | None = None,
) -> dict:
    os_info = read_os_release(os_release_text)
    applied = updates_applied(log_text, package_manager)
    report_warnings = list(warnings or [])
    if reboot_check == "running-kernel":
        report_warnings.append("reboot detection compared the running kernel only")
    if applied is None:
        report_warnings.append("package manager output did not show whether updates were applied")
    return {
        "run_id": run_id,
        "instance_id": instance_id,
        "os": os_info,
        "package_manager": package_manager,
        "started_at": started_at,
        "ended_at": ended_at,
        "exit_status": exit_status,
        "updates_applied": applied,
        "upgrade_summary": upgrade_summary(log_text),
        "reboot_required": reboot_required,
        "reboot_check": reboot_check,
        "reboot_performed": False,
        "ssm_recovery": "not-required" if not reboot_required else "pending",
        "warnings": report_warnings,
        "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def apply_reboot_result(report: dict, *, performed: bool, recovery: str) -> dict:
    updated = dict(report)
    updated["reboot_performed"] = performed
    updated["ssm_recovery"] = recovery
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write patch-report.json on the instance.")
    parser.add_argument("--os-release", type=Path)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--package-manager", default="")
    parser.add_argument("--started-at", default="")
    parser.add_argument("--ended-at", default="")
    parser.add_argument("--exit-status", type=int, default=0)
    parser.add_argument("--reboot-required", default="false")
    parser.add_argument("--reboot-check", default="")
    parser.add_argument("--mark-reboot", action="store_true")
    parser.add_argument("--reboot-performed", default="false")
    parser.add_argument("--ssm-recovery", default="")
    args = parser.parse_args(argv)
    if args.mark_reboot:
        report = json.loads(args.output.read_text(encoding="utf-8"))
        report = apply_reboot_result(
            report,
            performed=args.reboot_performed == "true",
            recovery=args.ssm_recovery,
        )
    else:
        report = build_patch_report(
            run_id=args.run_id,
            instance_id=args.instance_id,
            os_release_text=args.os_release.read_text(encoding="utf-8") if args.os_release else "",
            package_manager=args.package_manager,
            started_at=args.started_at,
            ended_at=args.ended_at,
            exit_status=args.exit_status,
            reboot_required=args.reboot_required == "true",
            reboot_check=args.reboot_check,
            log_text=args.log.read_text(encoding="utf-8") if args.log and args.log.is_file() else "",
        )
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "stage": "patch",
                "exit_status": report["exit_status"],
                "reboot_required": report["reboot_required"],
                "package_manager": report["package_manager"],
                "updates_applied": report["updates_applied"],
            }
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
