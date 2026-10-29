"""Launch and terminate only the instances this run tagged."""

from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from ami_patcher.aws_session import error_code
from ami_patcher.config import AmiId, AmiNameQuery, Config
from ami_patcher.errors import WorkflowError
from ami_patcher.exit_codes import EXIT_CHECKS_FAILED

_DEAD = {"shutting-down", "terminated", "stopping", "stopped"}


def resolve_image(ec2: Any, source: AmiId | AmiNameQuery) -> dict:
    if isinstance(source, AmiId):
        try:
            response = ec2.describe_images(ImageIds=[source.ami_id])
        except ClientError as exc:
            if error_code(exc) in {"InvalidAMIID.NotFound", "InvalidAMIID.Malformed"}:
                raise WorkflowError(f"source AMI {source.ami_id} was not found", EXIT_CHECKS_FAILED) from exc
            raise
        images = response.get("Images") or []
        if not images:
            raise WorkflowError(f"source AMI {source.ami_id} was not found", EXIT_CHECKS_FAILED)
    else:
        response = ec2.describe_images(
            Owners=[source.owner],
            Filters=[
                {"Name": "name", "Values": [source.name_pattern]},
                {"Name": "state", "Values": ["available"]},
            ],
        )
        images = response.get("Images") or []
        if not images:
            raise WorkflowError(
                f"no available AMI matches owner {source.owner} name {source.name_pattern}",
                EXIT_CHECKS_FAILED,
            )
    available = [image for image in images if image.get("State") == "available"]
    if not available:
        raise WorkflowError("source AMI is not available", EXIT_CHECKS_FAILED)
    available.sort(key=lambda image: (image.get("CreationDate") or "", image.get("ImageId") or ""))
    return available[-1]


def resolve_subnet(ec2: Any, config: Config) -> dict:
    if config.subnet_id:
        try:
            response = ec2.describe_subnets(SubnetIds=[config.subnet_id])
        except ClientError as exc:
            if error_code(exc) == "InvalidSubnetID.NotFound":
                raise WorkflowError(f"subnet {config.subnet_id} was not found", EXIT_CHECKS_FAILED) from exc
            raise
        subnets = response.get("Subnets") or []
        if not subnets:
            raise WorkflowError(f"subnet {config.subnet_id} was not found", EXIT_CHECKS_FAILED)
        return subnets[0]
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}]).get("Vpcs") or []
    if not vpcs:
        raise WorkflowError("subnet_id is unset and this region has no default VPC", EXIT_CHECKS_FAILED)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "default-for-az", "Values": ["true"]},
        ]
    ).get("Subnets") or []
    if not subnets:
        raise WorkflowError("subnet_id is unset and the default VPC has no default subnet", EXIT_CHECKS_FAILED)
    subnets.sort(key=lambda item: item.get("SubnetId") or "")
    return subnets[0]


def security_group(ec2: Any, group_id: str) -> dict:
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
    except ClientError as exc:
        if error_code(exc) == "InvalidGroup.NotFound":
            raise WorkflowError(f"security group {group_id} was not found", EXIT_CHECKS_FAILED) from exc
        raise
    groups = response.get("SecurityGroups") or []
    if not groups:
        raise WorkflowError(f"security group {group_id} was not found", EXIT_CHECKS_FAILED)
    return groups[0]


def launch_instance(
    ec2: Any,
    config: Config,
    image: dict,
    run_id: str,
    subnet_id: str,
    *,
    dry_run: bool = False,
) -> str | None:
    params = _launch_params(config, image, run_id, subnet_id)
    if dry_run:
        try:
            ec2.run_instances(**params, DryRun=True)
        except ClientError as exc:
            if error_code(exc) != "DryRunOperation":
                raise
        return None
    response = ec2.run_instances(**params)
    return str(response["Instances"][0]["InstanceId"])


def wait_until_running(
    ec2: Any,
    instance_id: str,
    timeout: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    _poll(
        timeout,
        sleep,
        lambda: _instance_state(ec2, instance_id),
        ready=lambda state: state == "running",
        failed=lambda state: state in _DEAD,
        what=f"instance {instance_id} to reach running",
    )


def wait_until_status_ok(
    ec2: Any,
    instance_id: str,
    timeout: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    def current() -> str:
        response = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
        statuses = response.get("InstanceStatuses") or []
        if not statuses:
            return "missing"
        instance_status = statuses[0].get("InstanceStatus", {}).get("Status")
        system_status = statuses[0].get("SystemStatus", {}).get("Status")
        if instance_status == "ok" and system_status == "ok":
            return "ok"
        return f"{instance_status}/{system_status}"

    _poll(
        timeout,
        sleep,
        current,
        ready=lambda state: state == "ok",
        failed=lambda state: False,
        what=f"instance {instance_id} status checks",
    )


def wait_until_ssm_online(
    ssm: Any,
    instance_id: str,
    timeout: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    def current() -> str:
        response = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        info = response.get("InstanceInformationList") or []
        if not info:
            return "missing"
        return str(info[0].get("PingStatus") or "missing")

    try:
        _poll(
            timeout,
            sleep,
            current,
            ready=lambda state: state == "Online",
            failed=lambda state: state == "ConnectionLost",
            what=f"SSM PingStatus Online for {instance_id}",
        )
    except WorkflowError as exc:
        raise WorkflowError(
            f"{exc}. Likely causes: the instance profile lacks AmazonSSMManagedInstanceCore, "
            "the SSM agent is not installed, or outbound HTTPS is blocked."
        ) from exc


def ssm_ping_status(ssm: Any, instance_id: str) -> str:
    response = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
    info = response.get("InstanceInformationList") or []
    if not info:
        return "missing"
    return str(info[0].get("PingStatus") or "missing")


def wait_until_ssm_recovered(
    ssm: Any,
    instance_id: str,
    timeout: int,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait until a reboot drops SSM, then until the agent is Online again."""
    deadline = time.monotonic() + timeout
    saw_drop = False
    while time.monotonic() <= deadline:
        if ssm_ping_status(ssm, instance_id) != "Online":
            saw_drop = True
            break
        sleep(2)
    if not saw_drop:
        raise WorkflowError(f"instance {instance_id} did not leave SSM Online after reboot was scheduled")
    while time.monotonic() <= deadline:
        if ssm_ping_status(ssm, instance_id) == "Online":
            return
        sleep(2)
    raise WorkflowError(f"timed out waiting for SSM Online after reboot of {instance_id}")


def list_project_instances(ec2: Any, project_tag: str, run_id: str | None = None) -> list[dict]:
    filters = [
        {"Name": "tag:Project", "Values": [project_tag]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ]
    if run_id is not None:
        filters.append({"Name": "tag:RunId", "Values": [run_id]})
    found: list[dict] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"Filters": filters}
        if token:
            kwargs["NextToken"] = token
        page = ec2.describe_instances(**kwargs)
        for reservation in page.get("Reservations") or []:
            found.extend(reservation.get("Instances") or [])
        token = page.get("NextToken")
        if not token:
            return found


def terminate_run(ec2: Any, project_tag: str, run_id: str) -> list[str]:
    ids = [str(instance["InstanceId"]) for instance in list_project_instances(ec2, project_tag, run_id)]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)
    return ids


def _launch_params(config: Config, image: dict, run_id: str, subnet_id: str) -> dict:
    if not config.security_group_id:
        raise WorkflowError("security_group_id is required before launch", EXIT_CHECKS_FAILED)
    root_name = image.get("RootDeviceName") or "/dev/sda1"
    ebs: dict[str, Any] = {"Encrypted": True, "DeleteOnTermination": True, "VolumeType": "gp3"}
    for mapping in image.get("BlockDeviceMappings") or []:
        if mapping.get("DeviceName") != root_name or "Ebs" not in mapping:
            continue
        source_ebs = mapping["Ebs"]
        if config.root_volume_size_gb:
            ebs["VolumeSize"] = config.root_volume_size_gb
        elif source_ebs.get("VolumeSize"):
            ebs["VolumeSize"] = source_ebs["VolumeSize"]
        if source_ebs.get("VolumeType"):
            ebs["VolumeType"] = source_ebs["VolumeType"]
        break
    tags = [
        {"Key": "Project", "Value": config.project_tag},
        {"Key": "RunId", "Value": run_id},
        {"Key": "Role", "Value": "build"},
        {"Key": "Name", "Value": f"ami-patcher-{run_id}"},
    ]
    return {
        "ImageId": image["ImageId"],
        "InstanceType": config.instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "IamInstanceProfile": {"Name": config.instance_profile_name},
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1},
        "SecurityGroupIds": [config.security_group_id],
        "SubnetId": subnet_id,
        "BlockDeviceMappings": [{"DeviceName": root_name, "Ebs": ebs}],
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": tags},
            {"ResourceType": "volume", "Tags": tags},
        ],
    }


def _instance_state(ec2: Any, instance_id: str) -> str:
    response = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations") or []
    if not reservations or not reservations[0].get("Instances"):
        return "missing"
    return str(reservations[0]["Instances"][0]["State"]["Name"])


def _poll(
    timeout: int,
    sleep: Callable[[float], None],
    current: Callable[[], str],
    *,
    ready: Callable[[str], bool],
    failed: Callable[[str], bool],
    what: str,
) -> None:
    deadline = time.monotonic() + timeout
    last = "missing"
    while True:
        last = current()
        if ready(last):
            return
        if failed(last):
            raise WorkflowError(f"gave up waiting for {what}; last state was {last}")
        if time.monotonic() > deadline:
            raise WorkflowError(f"timed out waiting for {what}; last state was {last}")
        sleep(2)
