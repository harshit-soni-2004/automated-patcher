"""Read-only checks. This does not launch or terminate anything."""

from __future__ import annotations

from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from ami_patcher.aws_session import AwsClients, error_code
from ami_patcher.config import Config
from ami_patcher.errors import WorkflowError
from ami_patcher.exceptions import ExceptionsError, load_exceptions
from ami_patcher.exit_codes import EXIT_CHECKS_FAILED, EXIT_INFRASTRUCTURE
from ami_patcher.instances import list_project_instances, resolve_image, resolve_subnet, security_group
from ami_patcher.redact import redact


@dataclass
class CheckReport:
    problems: list[str] = field(default_factory=list)
    source_ami_id: str | None = None
    subnet_id: str | None = None
    account: str | None = None


def run_check(config: Config, clients: AwsClients) -> CheckReport:
    report = CheckReport()
    try:
        config.require_for_launch()
    except Exception as exc:
        from ami_patcher.config import ConfigError

        if isinstance(exc, ConfigError):
            report.problems.extend(exc.errors)
            return report
        raise
    try:
        load_exceptions(config.exceptions_file)
    except ExceptionsError as exc:
        report.problems.extend(exc.errors)
        return report
    if config.bootstrap_ssm_agent:
        report.problems.append(
            "bootstrap_ssm_agent is not implemented; the source AMI must already include amazon-ssm-agent"
        )
    try:
        identity = clients.sts.get_caller_identity()
    except ClientError as exc:
        raise WorkflowError(redact(f"could not read AWS identity: {exc}"), EXIT_INFRASTRUCTURE) from exc
    report.account = str(identity.get("Account") or "")
    if report.account != config.account_id:
        report.problems.append(
            f"AWS account {report.account} does not match account_id {config.account_id}; refusing to continue"
        )
        return report
    try:
        image = resolve_image(clients.ec2, config.source_ami)
        group = security_group(clients.ec2, config.security_group_id or "")
        subnet = resolve_subnet(clients.ec2, config)
    except WorkflowError as exc:
        if exc.exit_code == EXIT_CHECKS_FAILED:
            report.problems.append(str(exc))
            return report
        raise
    report.source_ami_id = str(image.get("ImageId") or "")
    report.subnet_id = str(subnet.get("SubnetId") or "")
    if group.get("IpPermissions"):
        report.problems.append(f"security group {config.security_group_id} has inbound rules")
    if group.get("VpcId") != subnet.get("VpcId"):
        report.problems.append(
            f"security group VPC {group.get('VpcId')} does not match subnet VPC {subnet.get('VpcId')}"
        )
    _bucket_exists(clients, config.s3_bucket, report)
    _profile_exists(clients, config.instance_profile_name, report)
    orphans = list_project_instances(clients.ec2, config.project_tag)
    if orphans:
        ids = ", ".join(str(item.get("InstanceId")) for item in orphans)
        report.problems.append(f"orphaned project instances are still present: {ids}")
    return report


def _bucket_exists(clients: AwsClients, bucket: str, report: CheckReport) -> None:
    try:
        clients.s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = error_code(exc)
        if code in {"404", "NoSuchBucket", "NotFound"}:
            report.problems.append(f"S3 bucket {bucket} was not found")
            return
        raise WorkflowError(redact(f"could not read S3 bucket {bucket}: {exc}"), EXIT_INFRASTRUCTURE) from exc


def _profile_exists(clients: AwsClients, name: str, report: CheckReport) -> None:
    try:
        clients.iam.get_instance_profile(InstanceProfileName=name)
    except ClientError as exc:
        if error_code(exc) == "NoSuchEntity":
            report.problems.append(f"instance profile {name} was not found")
            return
        raise WorkflowError(redact(f"could not read instance profile {name}: {exc}"), EXIT_INFRASTRUCTURE) from exc
