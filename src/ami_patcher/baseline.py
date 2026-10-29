"""Baseline scan, package update, post-patch scan, and comparison. AMI creation is later."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from uuid import uuid4

from filelock import FileLock, Timeout

from ami_patcher.aws_session import AwsClients
from ami_patcher.config import Config
from ami_patcher.errors import WorkflowError
from ami_patcher.exit_codes import EXIT_ALREADY_RUNNING, EXIT_CHECKS_FAILED, EXIT_INFRASTRUCTURE, EXIT_OK
from ami_patcher.instances import (
    launch_instance,
    resolve_image,
    terminate_run,
    wait_until_running,
    wait_until_ssm_online,
    wait_until_ssm_recovered,
    wait_until_status_ok,
)
from ami_patcher.log import get_run_logger
from ami_patcher.preflight import run_check
from ami_patcher.remote_script import (
    baseline_object_keys,
    baseline_scan_script,
    comparison_object_key,
    comparison_script,
    file_delivery_scripts,
    finalize_patch_report_script,
    package_files,
    parse_status_line,
    patch_object_key,
    patch_script,
    reboot_script,
    report_object_keys,
    swap_cleanup_script,
)
from ami_patcher.s3_reports import object_exists
from ami_patcher.ssm_runner import CommandRunner, SsmRunCommand


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid4().hex[:8]}"


def run_baseline(
    config: Config,
    clients: AwsClients,
    *,
    run_id: str | None = None,
    dry_run: bool = False,
    keep_on_failure: bool = False,
    runner: CommandRunner | None = None,
    sleep: object = time.sleep,
) -> int:
    run_id = run_id or new_run_id()
    logger = get_run_logger(run_id)
    lock = FileLock(str(config.config_path.with_suffix(".lock")), timeout=0)
    try:
        lock.acquire()
    except Timeout:
        logger.error("stage=lock outcome=busy")
        return EXIT_ALREADY_RUNNING
    state: dict[str, str | None] = {"instance_id": None}
    exit_code = EXIT_OK
    try:
        exit_code = _execute(
            config,
            clients,
            run_id=run_id,
            dry_run=dry_run,
            runner=runner,
            sleep=sleep,
            logger=logger,
            state=state,
        )
    except WorkflowError as exc:
        logger.error("stage=baseline outcome=failed detail=%s", exc)
        exit_code = exc.exit_code
    except Exception as exc:
        logger.error("stage=baseline outcome=failed detail=%s", exc)
        exit_code = EXIT_INFRASTRUCTURE
    finally:
        instance_id = state["instance_id"]
        if instance_id:
            try:
                _must_succeed(
                    runner or SsmRunCommand(clients.ssm, sleep),
                    instance_id,
                    swap_cleanup_script(f"/var/tmp/ami-patcher/{run_id}"),
                    120,
                    f"{run_id} cleanup",
                )
                logger.info("stage=cleanup outcome=ok detail=workflow-swap instance_id=%s", instance_id)
            except Exception as exc:
                logger.error("stage=cleanup outcome=failed detail=%s", exc)
                if exit_code == EXIT_OK:
                    exit_code = EXIT_INFRASTRUCTURE
        if instance_id and (exit_code == EXIT_OK or not keep_on_failure):
            try:
                terminated = terminate_run(clients.ec2, config.project_tag, run_id)
                logger.info("stage=cleanup outcome=ok instance_ids=%s", ",".join(terminated) or "none")
            except Exception as exc:
                logger.error("stage=cleanup outcome=failed instance_id=%s detail=%s", instance_id, exc)
                if exit_code == EXIT_OK:
                    exit_code = EXIT_INFRASTRUCTURE
        elif instance_id:
            logger.error("stage=cleanup outcome=skipped instance_id=%s reason=keep-on-failure", instance_id)
        lock.release()
    return exit_code


def _execute(config, clients, *, run_id, dry_run, runner, sleep, logger, state):
    report = run_check(config, clients)
    if report.problems:
        for problem in report.problems:
            logger.error("stage=check outcome=failed detail=%s", problem)
        return EXIT_CHECKS_FAILED
    if not report.source_ami_id or not report.subnet_id:
        logger.error("stage=check outcome=failed detail=source AMI or subnet was not resolved")
        return EXIT_CHECKS_FAILED
    image = resolve_image(clients.ec2, config.source_ami)
    logger.info(
        "stage=check outcome=ok account=%s source_ami=%s subnet=%s",
        report.account,
        report.source_ami_id,
        report.subnet_id,
    )
    if dry_run:
        launch_instance(clients.ec2, config, image, run_id, report.subnet_id, dry_run=True)
        logger.info(
            "stage=dry-run outcome=ok source_ami=%s subnet=%s root_volume_size_gb=%s",
            report.source_ami_id,
            report.subnet_id,
            config.root_volume_size_gb,
        )
        return EXIT_OK
    instance_id = launch_instance(clients.ec2, config, image, run_id, report.subnet_id)
    state["instance_id"] = instance_id
    logger.info("stage=launch outcome=ok instance_id=%s source_ami=%s root_volume_size_gb=%s", instance_id, report.source_ami_id, config.root_volume_size_gb)
    if not instance_id:
        raise WorkflowError("launch did not return an instance id")
    wait_until_running(clients.ec2, instance_id, config.phase_timeouts.launch_seconds, sleep)
    wait_until_status_ok(clients.ec2, instance_id, config.phase_timeouts.launch_seconds, sleep)
    logger.info("stage=status-checks outcome=ok instance_id=%s", instance_id)
    wait_until_ssm_online(clients.ssm, instance_id, config.phase_timeouts.ssm_online_seconds, sleep)
    logger.info("stage=ssm-online outcome=ok instance_id=%s", instance_id)
    command_runner = runner or SsmRunCommand(clients.ssm, sleep)
    workdir = f"/var/tmp/ami-patcher/{run_id}"
    for script in file_delivery_scripts(package_files(config.exceptions_file), f"{workdir}/lib"):
        _must_succeed(command_runner, instance_id, script, 120, f"{run_id} deliver")
    keys = baseline_object_keys(config.s3_prefix, run_id)
    scan = baseline_scan_script(
        workdir=workdir,
        bucket=config.s3_bucket,
        keys=keys,
        run_id=run_id,
        source_ami_id=report.source_ami_id,
        instance_id=instance_id,
        min_free_disk_gb=config.min_free_disk_gb,
    )
    result = _must_succeed(
        command_runner,
        instance_id,
        scan,
        config.phase_timeouts.command_seconds,
        f"{run_id} baseline",
    )
    status = parse_status_line(result.stdout)
    logger.info(
        "stage=baseline-scan outcome=ok instance_id=%s scan_coverage=%s detected_rows=%s distinct_cves=%s accepted_rows=%s unresolved_rows=%s secret_count=%s",
        instance_id,
        status.get("scan_coverage"),
        status.get("detected_rows"),
        status.get("distinct_cves"),
        status.get("accepted_rows"),
        status.get("unresolved_rows"),
        status.get("secret_count"),
    )
    for name, key in keys.items():
        if not object_exists(clients.s3, config.s3_bucket, key):
            raise WorkflowError(f"baseline report was not uploaded: s3://{config.s3_bucket}/{key}")
        logger.info("stage=baseline-upload outcome=ok report=%s key=%s", name, key)
    _patch_rescan_and_compare(
        config,
        clients,
        command_runner,
        run_id=run_id,
        instance_id=instance_id,
        source_ami_id=report.source_ami_id,
        workdir=workdir,
        sleep=sleep,
        logger=logger,
    )
    logger.info(
        "stage=pipeline outcome=ok instance_id=%s note=ami-creation-is-not-part-of-this-milestone",
        instance_id,
    )
    return EXIT_OK


def _patch_rescan_and_compare(config, clients, runner, *, run_id, instance_id, source_ami_id, workdir, sleep, logger):
    patch_key = patch_object_key(config.s3_prefix, run_id)
    result = _must_succeed(
        runner,
        instance_id,
        patch_script(
            workdir=workdir,
            bucket=config.s3_bucket,
            patch_key=patch_key,
            run_id=run_id,
            instance_id=instance_id,
            min_free_disk_gb=config.min_free_disk_gb,
        ),
        config.phase_timeouts.dnf_update_seconds,
        f"{run_id} patch",
    )
    status = parse_status_line(result.stdout, stage="patch")
    if int(status.get("exit_status") or 0) != 0:
        raise WorkflowError("patch command reported a failure")
    if not object_exists(clients.s3, config.s3_bucket, patch_key):
        raise WorkflowError(f"patch report was not uploaded: s3://{config.s3_bucket}/{patch_key}")
    logger.info(
        "stage=patch outcome=ok instance_id=%s package_manager=%s updates_applied=%s reboot_required=%s",
        instance_id,
        status.get("package_manager"),
        status.get("updates_applied"),
        status.get("reboot_required"),
    )
    if status.get("reboot_required") is True:
        _must_succeed(runner, instance_id, reboot_script(), config.phase_timeouts.reboot_seconds, f"{run_id} reboot")
        wait_until_ssm_recovered(clients.ssm, instance_id, config.phase_timeouts.reboot_seconds, sleep)
        logger.info("stage=reboot outcome=ok instance_id=%s", instance_id)
        _must_succeed(
            runner,
            instance_id,
            finalize_patch_report_script(
                workdir=workdir,
                bucket=config.s3_bucket,
                patch_key=patch_key,
                performed=True,
                recovery="online",
            ),
            120,
            f"{run_id} patch",
        )
    else:
        logger.info("stage=reboot outcome=skipped instance_id=%s reason=not-required", instance_id)
    post_keys = report_object_keys(config.s3_prefix, run_id, "post-patch")
    post_result = _must_succeed(
        runner,
        instance_id,
        baseline_scan_script(
            workdir=workdir,
            bucket=config.s3_bucket,
            keys=post_keys,
            run_id=run_id,
            source_ami_id=source_ami_id,
            instance_id=instance_id,
            min_free_disk_gb=config.min_free_disk_gb,
            report_dir="post-patch",
        ),
        config.phase_timeouts.command_seconds,
        f"{run_id} post-patch",
    )
    post_status = parse_status_line(post_result.stdout)
    logger.info(
        "stage=post-patch-scan outcome=ok instance_id=%s scan_coverage=%s detected_rows=%s distinct_cves=%s",
        instance_id,
        post_status.get("scan_coverage"),
        post_status.get("detected_rows"),
        post_status.get("distinct_cves"),
    )
    for name, key in post_keys.items():
        if not object_exists(clients.s3, config.s3_bucket, key):
            raise WorkflowError(f"post-patch report was not uploaded: s3://{config.s3_bucket}/{key}")
        logger.info("stage=post-patch-upload outcome=ok report=%s key=%s", name, key)
    comparison_key = comparison_object_key(config.s3_prefix, run_id)
    baseline_prefix = "/".join(part for part in (config.s3_prefix.strip("/"), run_id, "baseline") if part)
    post_prefix = "/".join(part for part in (config.s3_prefix.strip("/"), run_id, "post-patch") if part)
    comparison = _must_succeed(
        runner,
        instance_id,
        comparison_script(
            workdir=workdir,
            bucket=config.s3_bucket,
            comparison_key=comparison_key,
            run_id=run_id,
            baseline_prefix=baseline_prefix,
            post_prefix=post_prefix,
        ),
        config.phase_timeouts.command_seconds,
        f"{run_id} comparison",
    )
    comparison_status = parse_status_line(comparison.stdout, stage="comparison")
    if not object_exists(clients.s3, config.s3_bucket, comparison_key):
        raise WorkflowError(f"comparison report was not uploaded: s3://{config.s3_bucket}/{comparison_key}")
    logger.info(
        "stage=comparison outcome=ok comparison_valid=%s raw_resolved=%s raw_remaining=%s raw_new=%s",
        comparison_status.get("comparison_valid"),
        comparison_status.get("raw_resolved"),
        comparison_status.get("raw_remaining"),
        comparison_status.get("raw_new"),
    )


def _must_succeed(runner: CommandRunner, instance_id: str, script: str, timeout: int, comment: str):
    command_id = runner.send(instance_id, script, timeout, comment)
    logger = get_run_logger(comment.split()[0] if comment else "-")
    logger.info("stage=ssm-command outcome=sent command_id=%s instance_id=%s", command_id, instance_id)
    result = runner.wait(instance_id, command_id, timeout)
    if result.status != "Success" or result.response_code != 0:
        detail = (result.stderr or result.stdout or result.status)[-500:]
        raise WorkflowError(f"SSM command {command_id} {result.status} response={result.response_code} {detail}")
    return result
