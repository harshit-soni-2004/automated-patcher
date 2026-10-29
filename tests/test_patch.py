from __future__ import annotations

import json
from pathlib import Path

from ami_patcher.compare_reports import compare_scans
from ami_patcher.exit_codes import EXIT_INFRASTRUCTURE, EXIT_OK
from ami_patcher.instances import launch_instance, wait_until_ssm_recovered
from ami_patcher.patch_report import build_patch_report, updates_applied
from ami_patcher.remote_script import (
    baseline_scan_script,
    comparison_object_key,
    comparison_script,
    patch_object_key,
    patch_script,
    reboot_script,
    report_object_keys,
)
from ami_patcher.ssm_runner import CommandResult
from ami_patcher.trivy import parse_scan
from tests.aws_fakes import source_image, write_config
from tests.test_baseline import INSTANCE_ID, STATUS, FakeRunner, _ready, run_baseline


def _patch(tmp_path: Path) -> str:
    config = write_config(tmp_path)
    return patch_script(
        workdir="/var/tmp/ami-patcher/run123",
        bucket=config.s3_bucket,
        patch_key=patch_object_key(config.s3_prefix, "run123"),
        run_id="run123",
        instance_id=INSTANCE_ID,
        min_free_disk_gb=2,
    )


def test_ubuntu_patch_script_upgrades_without_a_release_upgrade(tmp_path) -> None:
    script = _patch(tmp_path)
    assert "ubuntu|debian) family=deb" in script
    assert "pm=apt-get" in script
    assert "apt-get update" in script
    assert "apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade" in script
    assert "dist-upgrade" not in script
    assert "do-release-upgrade" not in script
    assert "full-upgrade" not in script
    assert "/var/run/reboot-required" in script
    assert "package manager lock, retry" in script
    assert "attempt\" -le 5" in script or '[ "$attempt" -le 5 ]' in script
    assert "Swap was not created and does not fix disk exhaustion." in script
    assert script.index("free disk") < script.index("apt-get update")
    assert "--skip-java-db" not in script


def test_rpm_patch_script_uses_the_detected_package_manager(tmp_path) -> None:
    script = _patch(tmp_path)
    assert "command -v dnf" in script
    assert "command -v yum" in script
    assert '"$pm" upgrade -y' in script
    assert "needs-restarting -r" in script
    assert "neither dnf nor yum is installed" in script
    assert "unsupported OS" in script
    assert "system-upgrade" not in script


def test_reboot_script_schedules_reboot_without_ssh() -> None:
    script = reboot_script()
    assert '"stage":"reboot"' in script
    assert "reboot" in script
    assert "ssh " not in script


def test_post_patch_reports_use_a_separate_prefix() -> None:
    keys = report_object_keys("ami-patcher-personal", "run123", "post-patch")
    script = baseline_scan_script(
        workdir="/var/tmp/ami-patcher/run123",
        bucket="bucket",
        keys=keys,
        run_id="run123",
        source_ami_id="ami-00253d81e1c983f9e",
        instance_id=INSTANCE_ID,
        min_free_disk_gb=2,
        report_dir="post-patch",
    )
    assert "/post-patch/trivy-report.json" in script
    assert "s3://bucket/ami-patcher-personal/run123/post-patch/trivy-report.json" in script
    assert "--skip-java-db" not in script
    assert "--pkg-types" in script
    assert patch_object_key("ami-patcher-personal", "run123").endswith("/patch/patch-report.json")
    assert comparison_object_key("ami-patcher-personal", "run123").endswith("/comparison/comparison.json")


def test_patch_report_records_outcome_without_claiming_a_reboot() -> None:
    report = build_patch_report(
        run_id="run123",
        instance_id=INSTANCE_ID,
        os_release_text='ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04"\n',
        package_manager="apt-get",
        started_at="2026-10-13T00:00:00Z",
        ended_at="2026-10-13T00:10:00Z",
        exit_status=0,
        reboot_required=True,
        reboot_check="reboot-required-file",
        log_text="3 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n",
    )
    assert report["os"]["version_id"] == "26.04"
    assert report["updates_applied"] is True
    assert report["reboot_required"] is True
    assert report["reboot_performed"] is False
    assert report["ssm_recovery"] == "pending"
    assert updates_applied("Nothing to do.\n", "dnf") is False


def test_comparison_matches_identities_and_rejects_coverage_mismatch() -> None:
    baseline = parse_scan(
        {
            "Results": [
                {
                    "Target": "ubuntu",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-2", "PkgName": "bash", "Severity": "CRITICAL"},
                    ],
                }
            ]
        }
    )
    post = parse_scan(
        {
            "Results": [
                {
                    "Target": "ubuntu",
                    "Class": "os-pkgs",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2", "PkgName": "bash", "Severity": "CRITICAL"},
                        {"VulnerabilityID": "CVE-3", "PkgName": "curl", "Severity": "HIGH"},
                    ],
                }
            ]
        }
    )
    same = compare_scans(
        baseline=baseline,
        post=post,
        baseline_summary={"scan_coverage": "os-only", "scanned_at": "t1", "unresolved_findings": [{"vulnerability_id": "CVE-1", "pkg_name": "openssl", "target": "ubuntu"}], "accepted_exceptions": []},
        post_summary={"scan_coverage": "os-only", "scanned_at": "t2", "unresolved_findings": [{"vulnerability_id": "CVE-3", "pkg_name": "curl", "target": "ubuntu"}], "accepted_exceptions": []},
        run_id="run123",
        baseline_report_prefix="ami-patcher-personal/run123/baseline",
        post_report_prefix="ami-patcher-personal/run123/post-patch",
    )
    assert same["comparison_valid"] is True
    assert same["raw"] == {"resolved": 1, "remaining": 1, "new": 1}
    assert same["unresolved"]["new"] == 1
    assert "not by itself a fix" in same["match_note"]
    mismatched = compare_scans(
        baseline=baseline,
        post=post,
        baseline_summary={"scan_coverage": "os-only", "unresolved_findings": [], "accepted_exceptions": []},
        post_summary={"scan_coverage": "full", "unresolved_findings": [], "accepted_exceptions": []},
        run_id="run123",
        baseline_report_prefix="a",
        post_report_prefix="b",
    )
    assert mismatched["comparison_valid"] is False
    assert "not a direct comparison" in mismatched["matching_limitation"]


def test_patch_failure_does_not_start_the_post_patch_scan(tmp_path) -> None:
    config, clients = _ready(tmp_path)

    class FailingPatch:
        def __init__(self):
            self.scripts: list[str] = []

        def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str:
            self.scripts.append(script)
            return "cmd"

        def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
            if "apt-get -y -o Dpkg::Options::=--force-confdef" in self.scripts[-1]:
                return CommandResult("Failed", "", "package manager command failed", 1)
            if "trivy rootfs" in self.scripts[-1]:
                return CommandResult(
                    "Success",
                    '{"stage":"baseline","scan_exit":0,"secret_exit":0,"upload_exit":0,"detected_rows":1,"distinct_cves":1,"accepted_rows":0,"unresolved_rows":1,"secret_count":0,"scan_coverage":"os-only"}\n',
                    "",
                    0,
                )
            return CommandResult("Success", "", "", 0)

    runner = FailingPatch()
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    assert sum("trivy rootfs" in script for script in runner.scripts) == 1
    assert not any("python3 -m ami_patcher.compare_reports" in script for script in runner.scripts)
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])
    clients.ec2.deregister_image.assert_not_called()


def test_patch_timeout_does_not_start_the_post_patch_scan(tmp_path) -> None:
    config, clients = _ready(tmp_path)

    class TimedOutPatch:
        def __init__(self):
            self.scripts: list[str] = []

        def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str:
            self.scripts.append(script)
            return "cmd"

        def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
            if "apt-get -y -o Dpkg::Options::=--force-confdef" in self.scripts[-1]:
                return CommandResult("TimedOut", "", "timed out", 1)
            if "trivy rootfs" in self.scripts[-1]:
                return CommandResult(
                    "Success",
                    '{"stage":"baseline","scan_exit":0,"secret_exit":0,"upload_exit":0,"detected_rows":1,"distinct_cves":1,"accepted_rows":0,"unresolved_rows":1,"secret_count":0,"scan_coverage":"os-only"}\n',
                    "",
                    0,
                )
            return CommandResult("Success", "", "", 0)

    runner = TimedOutPatch()
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    assert sum("trivy rootfs" in script for script in runner.scripts) == 1
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])


def test_reboot_waits_for_ssm_and_missing_post_patch_object_fails(tmp_path) -> None:
    config, clients = _ready(tmp_path)
    clients.ssm.describe_instance_information.side_effect = [
        {"InstanceInformationList": [{"PingStatus": "Online"}]},
        {"InstanceInformationList": [{"PingStatus": "ConnectionLost"}]},
        {"InstanceInformationList": [{"PingStatus": "Online"}]},
    ]

    class RebootRunner:
        def __init__(self):
            self.scripts: list[str] = []

        def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str:
            self.scripts.append(script)
            return "cmd"

        def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
            script = self.scripts[-1]
            if "apt-get -y -o Dpkg::Options::=--force-confdef" in script:
                return CommandResult(
                    "Success",
                    '{"stage":"patch","exit_status":0,"reboot_required":true,"package_manager":"apt-get","updates_applied":true}\n',
                    "",
                    0,
                )
            if "compare_reports" in script:
                return CommandResult("Success", '{"stage":"comparison","comparison_valid":true,"raw_resolved":0,"raw_remaining":0,"raw_new":0}\n', "", 0)
            if "trivy rootfs" in script:
                return CommandResult(
                    "Success",
                    '{"stage":"baseline","scan_exit":0,"secret_exit":0,"upload_exit":0,"detected_rows":1,"distinct_cves":1,"accepted_rows":0,"unresolved_rows":1,"secret_count":0,"scan_coverage":"os-only"}\n',
                    "",
                    0,
                )
            return CommandResult("Success", '{"stage":"reboot","scheduled":true}\n', "", 0)

    runner = RebootRunner()
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_OK
    assert any("(sleep 5; reboot)" in script for script in runner.scripts)
    assert any("--mark-reboot" in script for script in runner.scripts)
    assert any("/post-patch/" in script for script in runner.scripts)
    verified = [call.kwargs["Key"] for call in clients.s3.head_object.call_args_list]
    prefix = "ami-patcher/run123"
    for key in (
        f"{prefix}/baseline/trivy-report.json",
        f"{prefix}/baseline/summary.json",
        f"{prefix}/patch/patch-report.json",
        f"{prefix}/post-patch/trivy-report.json",
        f"{prefix}/post-patch/trivy-report.txt",
        f"{prefix}/post-patch/summary.json",
        f"{prefix}/comparison/comparison.json",
    ):
        assert key in verified
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])


def test_missing_post_patch_object_fails_and_still_terminates(tmp_path) -> None:
    from tests.aws_fakes import client_error

    config, clients = _ready(tmp_path)

    def head_object(**kwargs):
        if "/post-patch/" in kwargs["Key"]:
            raise client_error("404", "HeadObject")
        return {"ContentLength": 20}

    clients.s3.head_object.side_effect = head_object
    runner = FakeRunner(CommandResult("Success", STATUS, "", 0))
    code = run_baseline(config, clients, run_id="run123", runner=runner, sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    assert any("trivy rootfs" in script and "/post-patch/trivy-report.json" in script for script in runner.scripts)
    assert not any("python3 -m ami_patcher.compare_reports" in script for script in runner.scripts)
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])


def test_swap_cleanup_failure_is_surfaced_and_the_instance_is_still_terminated(tmp_path) -> None:
    config, clients = _ready(tmp_path)

    class CleanupFails(FakeRunner):
        def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
            if "swapoff" in self.scripts[-1]:
                return CommandResult("Failed", "", "cleanup failed: could not disable workflow swap", 1)
            return super().wait(instance_id, command_id, timeout)

    code = run_baseline(config, clients, run_id="run123", runner=CleanupFails(CommandResult("Success", STATUS, "", 0)), sleep=lambda _seconds: None)
    assert code == EXIT_INFRASTRUCTURE
    clients.ec2.terminate_instances.assert_called_once_with(InstanceIds=[INSTANCE_ID])


def test_ssm_recovery_times_out_when_the_instance_never_drops_offline() -> None:
    from unittest.mock import MagicMock

    ssm = MagicMock()
    ssm.describe_instance_information.return_value = {"InstanceInformationList": [{"PingStatus": "Online"}]}
    try:
        wait_until_ssm_recovered(ssm, INSTANCE_ID, 0, sleep=lambda _seconds: None)
    except Exception as exc:
        assert "did not leave SSM Online" in str(exc)
    else:
        raise AssertionError("expected a timeout")


def test_launch_still_requests_16_gib(tmp_path) -> None:
    config = write_config(tmp_path, root_volume_size_gb=16)
    image = source_image()
    image["BlockDeviceMappings"][0]["Ebs"]["VolumeSize"] = 8
    from unittest.mock import MagicMock

    ec2 = MagicMock()
    ec2.run_instances.return_value = {"Instances": [{"InstanceId": INSTANCE_ID}]}
    launch_instance(ec2, config, image, "run123", "subnet-0123456789abcdef0")
    ebs = ec2.run_instances.call_args.kwargs["BlockDeviceMappings"][0]["Ebs"]
    assert ebs["VolumeSize"] == 16
    assert ebs["VolumeType"] == "gp3"


def test_comparison_script_uploads_the_comparison_object(tmp_path) -> None:
    script = comparison_script(
        workdir="/var/tmp/ami-patcher/run123",
        bucket="bucket",
        comparison_key=comparison_object_key("ami-patcher-personal", "run123"),
        run_id="run123",
        baseline_prefix="ami-patcher-personal/run123/baseline",
        post_prefix="ami-patcher-personal/run123/post-patch",
    )
    assert "s3://bucket/ami-patcher-personal/run123/comparison/comparison.json" in script
    assert "compare_reports" in script
    json.loads("{}")
