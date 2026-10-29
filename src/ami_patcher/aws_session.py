"""boto3 session factory. Tests inject clients and never call this."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError


@dataclass
class AwsClients:
    ec2: Any
    ssm: Any
    s3: Any
    iam: Any
    sts: Any


def default_clients(region: str) -> AwsClients:
    session = boto3.Session(region_name=region)
    return AwsClients(
        ec2=session.client("ec2", region_name=region),
        ssm=session.client("ssm", region_name=region),
        s3=session.client("s3", region_name=region),
        iam=session.client("iam", region_name=region),
        sts=session.client("sts", region_name=region),
    )


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))
