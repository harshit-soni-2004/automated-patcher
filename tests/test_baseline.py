from __future__ import annotations

import base64
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock

from ami_patcher.baseline import run_baseline
from ami_patcher.baseline_summary import write_summary
from ami_patcher.exit_codes import EXIT_ALREADY_RUNNING, EXIT_CHECKS_FAILED, EXIT_INFRASTRUCTURE, EXIT_OK
from ami_patcher.instances import launch_instance
from ami_patcher.remote_script import baseline_object_keys, baseline_scan_script, file_delivery_scripts, package_files, parse_status_line
from ami_patcher.ssm_runner import CommandResult, SsmRunCommand
from filelock import FileLock
from tests.aws_fakes import ROOT, client_error, source_image, write_config

FIXTURES = Path(__file__).resolve().parent / "fixtures"
INSTANCE_ID = "i-0123456789abcdef0"
STATUS = (
    '{"stage":"baseline","scan_exit":0,"secret_exit":0,"upload_exit":0,'
    '"detected_rows":7,"distinct_cves":4,"accepted_rows":3,"unresolved_rows":4,"secret_count":3}\n'
)


class FakeRunner:
    def __init__(self, scan_result: CommandResult):
        self.scripts: list[str] = []
        self.scan_result = scan_result

    def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str:
        self.scripts.append(script)
        return f"cmd-{len(self.scripts)}"

    def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
        script = self.scripts[-1]
        if "trivy rootfs" in script:
            return self.scan_result
        if "apt-get -y -o Dpkg::Options::=--force-confdef" in script:
            return CommandResult(
                "Success",
                '{"stage":"patch","exit_status":0,"reboot_required":false,"package_manager":"apt-get","updates_applied":false}\n',
                "",
                0,
            )
        if "compare_reports" in script:
            return CommandResult(
                "Success",
                '{"stage":"comparison","comparison_valid":true,"raw_resolved":0,"raw_remaining":0,"raw_new":0}\n',
                "",
                0,
            )
        return CommandResult("Success", "", "", 0)


def _ready(tmp_path, *, head_missing: bool = False):
    config = write_config(tmp_path)
    ec2 = MagicMock()
    ec2.describe_images.return_value = {"Images": [source_image()]}
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "VpcId": "vpc-1", "IpPermissions": []}]
    }
    ec2.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-0123456789abcdef0", "VpcId": "vpc-1"}]}
    ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}

    def describe_instances(**kwargs):
        if kwargs.get("InstanceIds"):
            return {"Reservations": [{"Instances": [{"InstanceId": INSTANCE_ID, "State": {"Name": "running"}}]}]}
        names = {item["Name"] for item in kwargs.get("Filters") or []}
        if "tag:RunId" in names:
            return {"Reservations": [{"Instances": [{"InstanceId": INSTANCE_ID}]}]}
        return {"Reservations": []}

    ec2.describe_instances.side_effect = describe_instances
    ec2.describe_instance_status.return_value = {
        "InstanceStatuses": [{"InstanceStatus": {"Status": "ok"}, "SystemStatus": {"Status": "ok"}}]
    }
    ssm = MagicMock()
    ssm.describe_instance_information.return_value = {"InstanceInformationList": [{"PingStatus": "Online"}]}
    s3 = MagicMock()
    if head_missing:
        s3.head_object.side_effect = client_error("404", "HeadObject")
    else:
        s3.head_object.return_value = {"ContentLength": 20}
    clients = MagicMock()
    clients.ec2 = ec2
    clients.ssm = ssm
    clients.s3 = s3
    clients.iam = MagicMock()
    clients.sts = MagicMock()
    clients.sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev"}
    return config, clients


def test_launch_parameters_have_no_key_and_keep_the_ami_volume_size(tmp_path) -> None:
    config = write_config(tmp_path)
    ec2 = MagicMock()
    ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    instance_id = launch_instance(ec2, config, source_image(), "run123", "subnet-0123456789abcdef0")
    assert instance_id == INSTANCE_ID
    params = ec2.run_instances.call_args.kwargs
    assert "KeyName" not in params
    assert params["MetadataOptions"]["HttpTokens"] == "required"
    assert params["BlockDeviceMappings"][0]["Ebs"]["Encrypted"] is True
    assert params["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"] == 16
    assert params["ImageId"] == "ami-0123456789abcdef0"
    assert {tag["Key"] for tag in params["TagSpecifications"][0]["Tags"]} >= {"Project", "RunId", "Role"}


def test_launch_requests_16_gib_when_the_source_ami_is_smaller(tmp_path) -> None:
    config = write_config(tmp_path, root_volume_size_gb=16)
    image = source_image()
    image["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"] = 8
    ec2 = MagicMock()
    ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    launch_instance(ec2, config, image, "run123", "subnet-0123456789abcdef0")
    ebs = ec2.run_instances.call_args.kwargs["BlockDeviceMappings"][0]["Ebs"]
    assert ebs["VolumeSize"] == 16
    assert ebs["VolumeType"] == "gp3"
    assert ebs["Encrypted"] is True
    assert "Iops" not in ebs
    assert "Throughput" not in ebs


def _scan_script() -> str:
    keys = baseline_object_keys("ami-patcher", "run123")
    return baseline_scan_script(
        workdir="/var/tmp/ami-patcher/run123",
        bucket="ami-patcher-reports-example",
        keys=keys,
        run_id="run123",
        source_ami_id="ami-0123456789abcdef0",
        instance_id=INSTANCE_ID,
        min_free_disk_gb=2,
    )


def test_baseline_scan_script_uploads_from_the_instance() -> None:
    script = _scan_script()
    keys = baseline_object_keys("ami-patcher", "run123")
    assert "aws s3 cp" in script
    assert "trivy rootfs" in script
    assert "$basearch" in script
    assert "ssh " not in script
    assert "scp " not in script
    assert "paramiko" not in script
    assert "AKIA" not in script
    assert f"s3://ami-patcher-reports-example/{keys['json']}" in script
    assert "S3 upload was not attempted" in script
    assert "S3 upload failed; reports were not uploaded" in script


def test_scan_script_installs_trivy_with_apt_or_dnf() -> None:
    script = _scan_script()
    assert "ubuntu|debian) family=deb" in script
    assert "apt-get install -y trivy python3 python3-yaml" in script
    assert "https://aquasecurity.github.io/trivy-repo/deb generic main" in script
    assert "amzn|almalinux|rhel|centos|fedora|rocky|ol) family=rpm" in script
    assert "dnf install -y trivy python3 python3-pyyaml" in script
    assert "Trivy apt install failed" in script
    assert "Trivy dnf install failed" in script
    assert "releases/$basearch/" in script
    assert script.index("mkswap") < script.index("apt-get install -y trivy")
    assert script.index('export TMPDIR="$WORKDIR/tmp"') < script.index("trivy rootfs")
    assert 'fallocate -l "${SWAP_MB}M"' in script
    assert 'dd if=/dev/zero of="$workflow_swap" bs=1M count="$SWAP_MB"' in script
    assert "growpart" in script
    assert "resize2fs" in script
    assert '--cache-dir "$WORKDIR/trivy-cache"' in script
    assert "--pkg-types" in script
    assert "scan_coverage=os-only" in script
    assert "--skip-java-db" not in script
    assert "root disk is too low for swap" in script
    assert "existing swap is already configured" in script
    assert "swapoff" in script
    assert "partial OS-only scan" in script
    assert "need at least 2GiB" in script
    assert script.index("root disk is too low for swap") < script.index("fallocate -l")
    assert script.index("existing swap is already configured") < script.index("fallocate -l")


def test_scan_script_installs_aws_cli_or_fails_before_upload() -> None:
    script = _scan_script()
    assert "command -v aws" in script
    assert "https://awscli.amazonaws.com/$aws_zip" in script
    assert "Reports were not uploaded." in script
    aws_check = script.index("command -v aws")
    upload = script.index("aws s3 cp")
    assert aws_check < upload
    assert len(script.encode("utf-8")) < 20000
    files = package_files(ROOT / "exceptions.yaml")
    encoded = base64.b64encode(files["ami_patcher/trivy.py"]).decode()
    delivered = "".join(file_delivery_scripts(files, "/var/tmp/ami-patcher/run123/lib"))
    assert encoded[:1000] in delivered


def test_summary_keeps_exceptions_separate_from_remediation(tmp_path) -> None:
    output = tmp_path / "summary.json"
    status = write_summary(
        scan_path=FIXTURES / "trivy_before.json",
        secrets_path=FIXTURES / "trivy_null_and_secrets.json",
        exceptions_path=ROOT / "exceptions.yaml",
        output_path=output,
        run_id="run123",
        source_ami_id="ami-0123456789abcdef0",
        instance_id=INSTANCE_ID,
        trivy_version="0.75.0",
        scan_exit_status=0,
        secret_scan_exit_status=0,
        upload_exit_status=0,
        today=date(2026, 10, 12),
    )
    text = output.read_text(encoding="utf-8")
    assert '"remediated"' not in text
    assert status["unresolved_rows"] == 4
    assert status["accepted_rows"] == 3
    assert "Accepted exceptions are not remediated findings." in text
    assert parse_status_line("noise\n" + __import__("json").dumps(status) + "\n")["stage"] == "baseline"
    assert status["scan_coverage"] == "full"
    os_only = tmp_path / "os-only.json"
    os_status = write_summary(
        scan_path=FIXTURES / "trivy_before.json",
        secrets_path=FIXTURES / "trivy_null_and_secrets.json",
        exceptions_path=ROOT / "exceptions.yaml",
        output_path=os_only,
        run_id="run123",
        source_ami_id="ami-0123456789abcdef0",
        instance_id=INSTANCE_ID,
        trivy_version="0.75.0",
        scan_exit_status=0,
        secret_scan_exit_status=0,
        upload_exit_status=0,
        scan_coverage="os-only",
        today=date(2026, 10, 12),
    )
    os_text = os_only.read_text(encoding="utf-8")
    assert os_status["scan_coverage"] == "os-only"
    assert '"scan_coverage": "os-only"' in os_text
    assert "Partial OS-only scan" in os_text
    assert '"package_types": "os"' in os_text


def test_successful_baseline_terminates_only_the_run_instance(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    runner = FakeRunner(CommandResult("Success", STATUS, "", 0))
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_OK
    params = clients.ec2.run_instances.call_args.kwargs
    assert "KeyName" not in params
    assert any("trivy rootfs" in script for script in runner.scripts)
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])
    assert clients.ec2.deregister_image.called is False


def test_install_or_upload_failure_is_not_success_and_still_terminates(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    runner = FakeRunner(CommandResult("Failed", "", "Trivy apt install failed", 1))
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])
    assert clients.ec2.deregister_image.called is False


def test_failed_scan_is_not_treated_as_clean_and_keep_on_failure_skips_terminate(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    runner = FakeRunner(CommandResult("Failed", "", "trivy failed", 1))
    code = run_baseline(
        config,
        clients,
        run_id="run123",
        runner=runner,
        sleep=lambda _seconds: None,
        keep_on_failure=True,
    )
    assert code == EXIT_INFRASTRUCTURE
    clients.ec2.terminate_instances.assert_not_called()


def test_missing_s3_object_fails_and_still_cleans_up(tmp_path) -> None:
    config, clients = _ready(tmp_path, head_missing=True)
    runner = FakeRunner(CommandResult("Success", STATUS, "", 0))
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    clients.ec2.terminate_instances.assert_called_once()


def test_dry_run_does_not_send_commands(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    clients.ec2.run_instances.side_effect = client_error("DryRunOperation", "RunInstances")
    runner = FakeRunner(CommandResult("Success", STATUS, "", 0))
    code = run_baseline(config, clients, run_id="run123", dry_run=True, runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_OK
    assert runner.scripts == []
    clients.ec2.terminate_instances.assert_not_called()
    assert clients.ec2.run_instances.call_args.kwargs["DryRun"] is True


def test_second_local_run_is_rejected_while_the_lock_is_held(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    lock = FileLock(str(config.config_path.with_suffix(".lock")), timeout=0)
    lock.acquire()
    try:
        code = run_baseline(config, clients, run_id="run123", sleep=lambda _seconds: None)
    finally:
        lock.release()
    assert code == EXIT_ALREADY_RUNNING
    clients.ec2.run_instances.assert_not_called()


def test_check_failure_does_not_launch(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    clients.ec2.describe_security_groups.return_value = {
        "SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "VpcId": "vpc-1", "IpPermissions": [{"IpProtocol": "tcp"}]}]
    }
    code = run_baseline(config, clients, run_id="run123", sleep=lambda _seconds: None)
    assert code == EXIT_CHECKS_FAILED
    clients.ec2.run_instances.assert_not_called()


def test_ssm_runner_polls_until_success() -> None:
    ssm = MagicMock()
    ssm.send_command.return_value = {"Command": {"CommandId": "cmd-1"}}
    ssm.get_command_invocation.side_effect = [
        client_error("InvocationDoesNotExist", "GetCommandInvocation"),
        {"Status": "InProgress", "StandardOutputContent": "", "StandardErrorContent": "", "ResponseCode": -1},
        {"Status": "Success", "StandardOutputContent": STATUS, "StandardErrorContent": "", "ResponseCode": 0},
    ]
    runner = SsmRunCommand(ssm, sleep=lambda _seconds: None)
    command_id = runner.send(INSTANCE_ID, "echo hi", 30, "run123 baseline")
    result = runner.wait(INSTANCE_ID, command_id, 30)
    assert result.status == "Success"
    assert result.stdout == STATUS
    assert ssm.send_command.call_args.kwargs["Parameters"]["commands"] == ["echo hi"]
    assert "KeyName" not in ssm.send_command.call_args.kwargs
