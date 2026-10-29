from __future__ import annotations

import json
from pathlib import Path

from botocore.exceptions import ClientError

from ami_patcher.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def client_error(code: str, operation: str = "Operation") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


def write_config(tmp_path: Path, **overrides: str):
    fields = {
        "region": "ap-south-1",
        "source_ami": "ami-0123456789abcdef0",
        "new_ami_name_prefix": "Veefin-AlmaLinux9-Hardened",
        "instance_type": "t3.medium",
        "subnet_id": "subnet-0123456789abcdef0",
        "security_group_id": "sg-0123456789abcdef0",
        "instance_profile_name": "ami-patcher-instance",
        "s3_bucket": "ami-patcher-reports-example",
        "s3_prefix": "ami-patcher",
        "exceptions_file": (ROOT / "exceptions.yaml").as_posix(),
        "project_tag": "ami-patcher",
        "account_id": "123456789012",
    }
    fields.update(overrides)
    path = tmp_path / "config.yaml"
    path.write_text("".join(f"{key}: {json.dumps(value)}\n" for key, value in fields.items()), encoding="utf-8")
    return load_config(path)


def source_image() -> dict:
    return {
        "ImageId": "ami-0123456789abcdef0",
        "Name": "Veefin-AlmaLinux9-Hardened-2026-10-12",
        "State": "available",
        "CreationDate": "2026-10-12T08:00:00.000Z",
        "RootDeviceName": "/dev/sda1",
        "BlockDeviceMappings": [
            {"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 16, "VolumeType": "gp3"}}
        ],
    }
