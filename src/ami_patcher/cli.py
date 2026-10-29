"""Command line entry point."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from ami_patcher.aws_session import default_clients
from ami_patcher.baseline import run_baseline
from ami_patcher.config import ConfigError, load_config
from ami_patcher.errors import WorkflowError
from ami_patcher.exit_codes import EXIT_CHECKS_FAILED, EXIT_INFRASTRUCTURE, EXIT_OK
from ami_patcher.log import RedactFilter
from ami_patcher.preflight import run_check


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ami-patcher",
        description="Scan and patch a temporary EC2 instance, then compare the reports. AMI creation is later.",
    )
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("check", help="preflight checks")
    setup = subparsers.add_parser("setup", help="create the bucket, role, and security group")
    setup.add_argument("--dry-run", action="store_true")
    run = subparsers.add_parser("run", help="baseline scan, patch, post-patch scan, and comparison; AMI creation is later")
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--keep-on-failure", action="store_true")
    orphans = subparsers.add_parser("cleanup-orphans", help="terminate leftover project instances")
    orphans.add_argument("--older-than-hours", type=int, default=6)
    prune = subparsers.add_parser("prune", help="delete project AMIs beyond the retention count")
    prune.add_argument("--yes", action="store_true", help="actually delete; default is dry-run")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging()
    if args.command in {"setup", "cleanup-orphans", "prune"}:
        print(
            f"{args.command} is not available yet",
            file=sys.stderr,
        )
        return EXIT_INFRASTRUCTURE
    try:
        config = load_config(Path(args.config))
        config.require_for_launch()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return EXIT_CHECKS_FAILED
    if args.command == "check":
        return _check(config)
    if args.command == "run":
        return run_baseline(
            config,
            default_clients(config.region),
            dry_run=args.dry_run,
            keep_on_failure=args.keep_on_failure,
        )
    print(f"unknown command {args.command}", file=sys.stderr)
    return EXIT_INFRASTRUCTURE


def _check(config) -> int:
    try:
        report = run_check(config, default_clients(config.region))
    except WorkflowError as exc:
        print(exc, file=sys.stderr)
        return exc.exit_code
    if report.problems:
        for problem in report.problems:
            print(problem, file=sys.stderr)
        return EXIT_CHECKS_FAILED
    print(
        f"check ok account={report.account} source_ami={report.source_ami_id} subnet={report.subnet_id}",
        file=sys.stderr,
    )
    return EXIT_OK


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s run_id=%(run_id)s %(message)s")
    handler_filters = logging.getLogger().handlers
    for handler in handler_filters:
        if not any(isinstance(existing, RedactFilter) for existing in handler.filters):
            handler.addFilter(RedactFilter())


if __name__ == "__main__":
    raise SystemExit(main())
