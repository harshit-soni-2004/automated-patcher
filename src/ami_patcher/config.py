"""Load and validate ami-patcher configuration.

Paths inside the file are resolved relative to the config file's directory,
not the process working directory, so a cron job can be started from anywhere.
Credential material is rejected and is never a config field.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ami_patcher.redact import secret_kinds

_AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")
_SECURITY_GROUP_ID = re.compile(r"^sg-[0-9a-f]{8,17}$")
_SUBNET_ID = re.compile(r"^subnet-[0-9a-f]{8,17}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_SNS_ARN = re.compile(r"^arn:aws(?:-cn|-us-gov)?:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]+$")
_ACCOUNT_ID = re.compile(r"^\d{12}$")
_AMI_OWNERS = {"self", "amazon", "aws-marketplace"}
_FORBIDDEN_KEYS = {
    "aws_access_key_id",
    "aws_secret_access_key",
    "aws_session_token",
    "access_key",
    "secret_key",
    "secret_access_key",
    "session_token",
}
_ALLOWED_KEYS = {
    "region",
    "source_ami",
    "new_ami_name_prefix",
    "instance_type",
    "subnet_id",
    "security_group_id",
    "instance_profile_name",
    "s3_bucket",
    "s3_prefix",
    "sns_topic_arn",
    "exceptions_file",
    "min_free_disk_gb",
    "phase_timeouts",
    "max_total_runtime_minutes",
    "keep_amis",
    "project_tag",
    "bootstrap_ssm_agent",
    "root_volume_size_gb",
    "account_id",
}
_TIMEOUT_DEFAULTS = {
    "launch_seconds": 600,
    "ssm_online_seconds": 900,
    "command_seconds": 1200,
    "dnf_update_seconds": 3600,
    "reboot_seconds": 900,
    "image_available_seconds": 1800,
}


class ConfigError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class AmiId:
    ami_id: str


@dataclass(frozen=True)
class AmiNameQuery:
    owner: str
    name_pattern: str


@dataclass(frozen=True)
class PhaseTimeouts:
    launch_seconds: int
    ssm_online_seconds: int
    command_seconds: int
    dnf_update_seconds: int
    reboot_seconds: int
    image_available_seconds: int


@dataclass(frozen=True)
class Config:
    region: str
    source_ami: AmiId | AmiNameQuery
    new_ami_name_prefix: str
    instance_type: str
    subnet_id: str | None
    security_group_id: str | None
    instance_profile_name: str
    s3_bucket: str
    s3_prefix: str
    sns_topic_arn: str | None
    exceptions_file: Path
    min_free_disk_gb: float
    phase_timeouts: PhaseTimeouts
    max_total_runtime_minutes: int
    keep_amis: int
    project_tag: str
    bootstrap_ssm_agent: bool
    root_volume_size_gb: int | None
    account_id: str | None
    config_path: Path

    def require_for_launch(self) -> None:
        """Fields a real launch needs. `setup` may run before a security group exists."""
        missing = []
        if not self.account_id:
            missing.append("account_id is required before check or run")
        if not self.security_group_id:
            missing.append("security_group_id is required before check or run")
        if missing:
            raise ConfigError(missing)


def load_config(path: Path) -> Config:
    config_path = path.expanduser().resolve()
    if not config_path.is_file():
        raise ConfigError([f"config file not found: {config_path}"])
    raw_text = config_path.read_text(encoding="utf-8")
    kinds = secret_kinds(raw_text)
    if kinds:
        raise ConfigError(
            [f"config contains credential-shaped material ({', '.join(kinds)}); remove it"]
        )
    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError([f"config is not valid YAML: {exc}"]) from exc
    if not isinstance(loaded, dict):
        raise ConfigError(["config must be a YAML mapping"])
    errors: list[str] = []
    _reject_forbidden_keys(loaded, errors)
    unknown = sorted(set(loaded) - _ALLOWED_KEYS)
    if unknown:
        errors.append(f"unknown config keys: {', '.join(unknown)}")
    if errors:
        raise ConfigError(errors)

    base = config_path.parent
    region = _required_str(loaded, "region", errors)
    source_ami = _parse_source_ami(loaded.get("source_ami"), errors)
    prefix = _required_str(loaded, "new_ami_name_prefix", errors)
    instance_type = _optional_str(loaded, "instance_type", "t3.medium", errors)
    subnet_id = _optional_id(loaded, "subnet_id", _SUBNET_ID, errors)
    security_group_id = _optional_id(loaded, "security_group_id", _SECURITY_GROUP_ID, errors)
    instance_profile_name = _required_str(loaded, "instance_profile_name", errors)
    bucket = _required_str(loaded, "s3_bucket", errors)
    if bucket and not _BUCKET.match(bucket):
        errors.append("s3_bucket is not a valid bucket name")
    s3_prefix = _optional_str(loaded, "s3_prefix", "ami-patcher", errors).strip("/")
    if ".." in s3_prefix.split("/") or "\\" in s3_prefix:
        errors.append("s3_prefix must be a relative S3 key prefix")
    sns_topic_arn = _optional_sns(loaded, errors)
    exceptions_file = _resolve_exceptions_file(loaded, base, errors)
    min_free = _optional_number(loaded, "min_free_disk_gb", 2, errors)
    if min_free is not None and min_free < 0:
        errors.append("min_free_disk_gb must be >= 0")
    timeouts = _parse_timeouts(loaded.get("phase_timeouts", {}), errors)
    max_runtime = _optional_int(loaded, "max_total_runtime_minutes", 180, errors)
    if max_runtime is not None and max_runtime < 1:
        errors.append("max_total_runtime_minutes must be >= 1")
    keep_amis = _optional_int(loaded, "keep_amis", 4, errors)
    if keep_amis is not None and keep_amis < 1:
        errors.append("keep_amis must be >= 1")
    project_tag = _optional_str(loaded, "project_tag", "ami-patcher", errors)
    if project_tag is not None and (not project_tag or len(project_tag) > 256 or "," in project_tag):
        errors.append("project_tag must be a non-empty tag value without commas")
    bootstrap = _optional_bool(loaded, "bootstrap_ssm_agent", False, errors)
    account_id = _parse_account_id(loaded, errors)
    root_volume = _optional_int_or_none(loaded, "root_volume_size_gb", errors)
    if root_volume is not None and not 8 <= root_volume <= 16384:
        errors.append("root_volume_size_gb must be between 8 and 16384 when set")
    if prefix is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._()-]{0,127}", prefix):
        errors.append("new_ami_name_prefix contains characters that are not valid in an AMI name")
    required_ok = all(
        value is not None
        for value in (
            region,
            source_ami,
            prefix,
            instance_type,
            instance_profile_name,
            bucket,
            s3_prefix,
            exceptions_file,
            min_free,
            timeouts,
            max_runtime,
            keep_amis,
            project_tag,
            bootstrap,
        )
    )
    if errors or not required_ok:
        raise ConfigError(errors or ["config is incomplete"])
    assert region and prefix and instance_type and instance_profile_name and bucket
    assert source_ami and exceptions_file and timeouts and s3_prefix and project_tag
    assert min_free is not None and max_runtime is not None and keep_amis is not None
    assert bootstrap is not None
    return Config(
        region=region,
        source_ami=source_ami,
        new_ami_name_prefix=prefix,
        instance_type=instance_type,
        subnet_id=subnet_id,
        security_group_id=security_group_id,
        instance_profile_name=instance_profile_name,
        s3_bucket=bucket,
        s3_prefix=s3_prefix,
        sns_topic_arn=sns_topic_arn,
        exceptions_file=exceptions_file,
        min_free_disk_gb=float(min_free),
        phase_timeouts=timeouts,
        max_total_runtime_minutes=max_runtime,
        keep_amis=keep_amis,
        project_tag=project_tag,
        bootstrap_ssm_agent=bootstrap,
        root_volume_size_gb=root_volume,
        account_id=account_id,
        config_path=config_path,
    )


def _reject_forbidden_keys(value: Any, errors: list[str], trail: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key)
            if name.lower() in _FORBIDDEN_KEYS:
                where = f"{trail}.{name}" if trail else name
                errors.append(f"config must not contain credential field {where}")
            _reject_forbidden_keys(child, errors, f"{trail}.{name}" if trail else name)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, errors, f"{trail}[{index}]")


def _parse_account_id(loaded: dict, errors: list[str]) -> str | None:
    if "account_id" not in loaded or loaded["account_id"] is None:
        return None
    value = loaded["account_id"]
    if isinstance(value, bool):
        errors.append("account_id must be a 12-digit AWS account id")
        return None
    if isinstance(value, int):
        text = str(value)
    elif isinstance(value, str):
        text = value.strip()
    else:
        errors.append("account_id must be a 12-digit AWS account id")
        return None
    if not text.isdigit() or len(text) != 12:
        errors.append("account_id must be a 12-digit AWS account id")
        return None
    return text


def _parse_source_ami(value: Any, errors: list[str]) -> AmiId | AmiNameQuery | None:
    if isinstance(value, str):
        if not _AMI_ID.match(value):
            errors.append("source_ami must be an AMI id such as ami-0123456789abcdef0")
            return None
        return AmiId(value)
    if isinstance(value, dict):
        extra = sorted(set(value) - {"owner", "name_pattern"})
        if extra:
            errors.append(f"source_ami contains unknown keys: {', '.join(extra)}")
        owner = value.get("owner")
        pattern = value.get("name_pattern")
        if not isinstance(owner, str) or not (
            owner in _AMI_OWNERS or _ACCOUNT_ID.match(owner)
        ):
            errors.append("source_ami.owner must be self, amazon, aws-marketplace, or a 12-digit account id")
            return None
        if not isinstance(pattern, str) or not pattern.strip():
            errors.append("source_ami.name_pattern is required")
            return None
        return AmiNameQuery(owner=owner, name_pattern=pattern.strip())
    errors.append("source_ami must be an AMI id or a mapping with owner and name_pattern")
    return None


def _parse_timeouts(value: Any, errors: list[str]) -> PhaseTimeouts | None:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        errors.append("phase_timeouts must be a mapping")
        return None
    before = len(errors)
    unknown = sorted(set(value) - set(_TIMEOUT_DEFAULTS))
    if unknown:
        errors.append(f"unknown phase_timeouts: {', '.join(unknown)}")
    merged = dict(_TIMEOUT_DEFAULTS)
    for key in _TIMEOUT_DEFAULTS:
        if key not in value:
            continue
        raw = value[key]
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
            errors.append(f"phase_timeouts.{key} must be an integer >= 1")
        else:
            merged[key] = raw
    if len(errors) > before:
        return None
    return PhaseTimeouts(**merged)


def _resolve_exceptions_file(loaded: dict, base: Path, errors: list[str]) -> Path | None:
    raw = loaded.get("exceptions_file")
    if not isinstance(raw, str) or not raw.strip():
        errors.append("exceptions_file is required")
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    path = path.resolve()
    if not path.is_file():
        errors.append(f"exceptions_file not found: {path}")
        return None
    return path


def _required_str(loaded: dict, key: str, errors: list[str]) -> str | None:
    value = loaded.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{key} is required")
        return None
    return value.strip()


def _optional_str(loaded: dict, key: str, default: str, errors: list[str]) -> str | None:
    if key not in loaded or loaded[key] is None:
        return default
    value = loaded[key]
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{key} must be a non-empty string")
        return None
    return value.strip()


def _optional_id(loaded: dict, key: str, pattern: re.Pattern[str], errors: list[str]) -> str | None:
    if key not in loaded or loaded[key] is None:
        return None
    value = loaded[key]
    if not isinstance(value, str) or not pattern.match(value):
        errors.append(f"{key} has an invalid id format")
        return None
    return value


def _optional_sns(loaded: dict, errors: list[str]) -> str | None:
    if "sns_topic_arn" not in loaded or loaded["sns_topic_arn"] is None:
        return None
    value = loaded["sns_topic_arn"]
    if not isinstance(value, str) or not _SNS_ARN.match(value):
        errors.append("sns_topic_arn must be an SNS topic ARN")
        return None
    return value


def _optional_number(loaded: dict, key: str, default: float, errors: list[str]) -> float | None:
    if key not in loaded or loaded[key] is None:
        return default
    value = loaded[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{key} must be a number")
        return None
    return float(value)


def _optional_int(loaded: dict, key: str, default: int, errors: list[str]) -> int | None:
    if key not in loaded or loaded[key] is None:
        return default
    value = loaded[key]
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{key} must be an integer")
        return None
    return value


def _optional_int_or_none(loaded: dict, key: str, errors: list[str]) -> int | None:
    if key not in loaded or loaded[key] is None:
        return None
    value = loaded[key]
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{key} must be an integer or null")
        return None
    return value


def _optional_bool(loaded: dict, key: str, default: bool, errors: list[str]) -> bool | None:
    if key not in loaded or loaded[key] is None:
        return default
    value = loaded[key]
    if not isinstance(value, bool):
        errors.append(f"{key} must be true or false")
        return None
    return value
