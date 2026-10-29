from __future__ import annotations

from ami_patcher.config import load_config
from ami_patcher.preflight import run_check
from tests.aws_fakes import client_error, source_image, write_config


def _clients(*, inbound: bool = False, orphans: bool = False, bucket_missing: bool = False):
    from unittest.mock import MagicMock

    ec2 = MagicMock()
    ec2.describe_images.return_value = {"Images": [source_image()]}
    ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-0123456789abcdef0",
                "VpcId": "vpc-1",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22}] if inbound else [],
            }
        ]
    }
    ec2.describe_subnets.return_value = {"Subnets": [{"SubnetId": "subnet-0123456789abcdef0", "VpcId": "vpc-1"}]}
    ec2.describe_instances.return_value = {
        "Reservations": [{"Instances": [{"InstanceId": "i-orphan"}]}] if orphans else []
    }
    s3 = MagicMock()
    if bucket_missing:
        s3.head_bucket.side_effect = client_error("404", "HeadBucket")
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/dev"}
    clients = MagicMock()
    clients.ec2 = ec2
    clients.s3 = s3
    clients.iam = MagicMock()
    clients.sts = sts
    clients.ssm = MagicMock()
    return clients


def test_check_stops_before_ec2_when_the_account_does_not_match(tmp_path) -> None:
    clients = _clients()
    clients.sts.get_caller_identity.return_value = {
        "Account": "999999999999",
        "Arn": "arn:aws:iam::999999999999:user/personal",
    }
    report = run_check(write_config(tmp_path), clients)
    assert any("does not match account_id" in problem for problem in report.problems)
    clients.ec2.describe_images.assert_not_called()
    clients.ec2.run_instances.assert_not_called()


def test_check_passes_when_prerequisites_exist(tmp_path) -> None:
    report = run_check(write_config(tmp_path), _clients())
    assert report.problems == []
    assert report.source_ami_id == "ami-0123456789abcdef0"
    assert report.account == "123456789012"
    assert report.subnet_id == "subnet-0123456789abcdef0"


def test_check_rejects_inbound_rules_orphans_and_missing_bucket(tmp_path) -> None:
    assert any("inbound" in problem for problem in run_check(write_config(tmp_path), _clients(inbound=True)).problems)
    assert any("i-orphan" in problem for problem in run_check(write_config(tmp_path), _clients(orphans=True)).problems)
    assert any("was not found" in problem for problem in run_check(write_config(tmp_path), _clients(bucket_missing=True)).problems)


def test_check_chooses_the_newest_matching_ami(tmp_path) -> None:
    write_config(tmp_path)
    path = tmp_path / "config.yaml"
    text = path.read_text(encoding="utf-8").replace(
        'source_ami: "ami-0123456789abcdef0"\n',
        "source_ami:\n  owner: self\n  name_pattern: Veefin-AlmaLinux9-Hardened-*\n",
    )
    path.write_text(text, encoding="utf-8")
    older = source_image()
    older["ImageId"] = "ami-0c81bfee8c8088f65"
    older["CreationDate"] = "2026-10-08T00:00:00.000Z"
    newest = source_image()
    newest["ImageId"] = "ami-0aaaaaaaaaaaaaaaa"
    newest["CreationDate"] = "2026-10-12T09:00:00.000Z"
    clients = _clients()
    clients.ec2.describe_images.return_value = {"Images": [older, newest]}
    report = run_check(load_config(path), clients)
    assert report.problems == []
    assert report.source_ami_id == "ami-0aaaaaaaaaaaaaaaa"
