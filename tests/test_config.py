from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from ami_patcher.config import AmiId, AmiNameQuery, ConfigError, load_config

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config.example.yaml"


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


def _base(tmp_path: Path, **overrides: str) -> str:
    exceptions = (ROOT / "exceptions.yaml").as_posix()
    fields = {
        "region": "ap-south-1",
        "source_ami": "ami-0123456789abcdef0",
        "new_ami_name_prefix": "Veefin-AlmaLinux9-Hardened",
        "instance_profile_name": "ami-patcher-instance",
        "s3_bucket": "ami-patcher-reports-example",
        "exceptions_file": exceptions,
    }
    fields.update(overrides)
    lines = [f"{key}: {json.dumps(value)}" for key, value in fields.items()]
    return "\n".join(lines) + "\n"


def test_example_config_loads_with_safe_defaults() -> None:
    config = load_config(EXAMPLE)
    assert config.region == "ap-south-1"
    assert config.account_id == "000000000000"
    assert isinstance(config.source_ami, AmiNameQuery)
    assert config.source_ami.owner == "self"
    assert config.source_ami.name_pattern == "Veefin-AlmaLinux9-Hardened-*"
    assert config.instance_type == "t3.medium"
    assert config.subnet_id is None
    assert config.security_group_id is None
    assert config.min_free_disk_gb == 2
    assert config.bootstrap_ssm_agent is False
    assert config.root_volume_size_gb is None
    assert config.keep_amis == 4
    assert config.project_tag == "ami-patcher"
    assert config.phase_timeouts.dnf_update_seconds == 3600
    assert config.exceptions_file == (ROOT / "exceptions.yaml").resolve()
    with pytest.raises(ConfigError, match="security_group_id"):
        config.require_for_launch()


def test_ami_id_source_and_launch_requirements(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        _base(tmp_path) + "security_group_id: sg-0123456789abcdef0\naccount_id: \"123456789012\"\n",
    )
    config = load_config(path)
    assert isinstance(config.source_ami, AmiId)
    assert config.source_ami.ami_id == "ami-0123456789abcdef0"
    config.require_for_launch()


def test_relative_exceptions_path_is_resolved_from_the_config_directory(tmp_path: Path) -> None:
    exceptions = tmp_path / "exceptions.yaml"
    exceptions.write_text((ROOT / "exceptions.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    path = _write_config(tmp_path, _base(tmp_path, exceptions_file="exceptions.yaml"))
    config = load_config(path)
    assert config.exceptions_file == exceptions.resolve()


def test_rejects_credential_material_and_forbidden_keys(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="aws-access-key"):
        load_config(_write_config(tmp_path, _base(tmp_path) + "note: AKIAIOSFODNN7EXAMPLE\n"))
    with pytest.raises(ConfigError, match="credential field"):
        load_config(_write_config(tmp_path, _base(tmp_path) + "access_key: example\n"))


def test_rejects_unknown_keys_bad_ids_and_missing_exceptions(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="unknown config keys"):
        load_config(_write_config(tmp_path, _base(tmp_path) + "extra: true\n"))
    with pytest.raises(ConfigError, match="source_ami"):
        load_config(_write_config(tmp_path, _base(tmp_path, source_ami="not-an-ami")))
    with pytest.raises(ConfigError, match="exceptions_file not found"):
        load_config(_write_config(tmp_path, _base(tmp_path, exceptions_file="missing.yaml")))
    with pytest.raises(ConfigError, match="root_volume_size_gb"):
        load_config(_write_config(tmp_path, _base(tmp_path) + "root_volume_size_gb: 4\n"))
    with pytest.raises(ConfigError, match="keep_amis"):
        load_config(_write_config(tmp_path, _base(tmp_path) + "keep_amis: 0\n"))


def test_partial_phase_timeouts_keep_the_other_defaults(tmp_path: Path) -> None:
    path = _write_config(tmp_path, _base(tmp_path) + "phase_timeouts:\n  reboot_seconds: 1200\n")
    config = load_config(path)
    assert config.phase_timeouts.reboot_seconds == 1200
    assert config.phase_timeouts.launch_seconds == 600
