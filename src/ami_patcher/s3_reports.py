"""Confirm the instance's own upload. This does not download report bodies."""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from ami_patcher.aws_session import error_code


def object_exists(s3: Any, bucket: str, key: str) -> bool:
    try:
        response = s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if error_code(exc) in {"404", "NoSuchKey", "NotFound"}:
            return False
        raise
    return int(response.get("ContentLength") or 0) > 0
