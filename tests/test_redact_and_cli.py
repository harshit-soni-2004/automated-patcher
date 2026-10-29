from __future__ import annotations

import logging
from pathlib import Path

import pytest

from ami_patcher.cli import main
from ami_patcher.log import get_run_logger
from ami_patcher.redact import redact, secret_kinds


PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
abcdefghijklmnopqrstuvwxyz0123456789
-----END OPENSSH PRIVATE KEY-----"""
SESSION = "FwoGZXIvYXdzEJz//////////wEaDExampleSessionToken12345"


def test_redacts_keys_tokens_assignments_and_private_keys() -> None:
    text = (
        "access AKIAIOSFODNN7EXAMPLE "
        f"session {SESSION} "
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        f"and {PRIVATE_KEY} "
        "cve CVE-2024-24790 stays"
    )
    cleaned = redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert SESSION not in cleaned
    assert "wJalrXUtnFEMI" not in cleaned
    assert "BEGIN OPENSSH PRIVATE KEY" not in cleaned
    assert "CVE-2024-24790" in cleaned
    assert redact(cleaned) == cleaned
    assert secret_kinds(text) == [
        "private-key",
        "aws-access-key",
        "aws-session-token",
        "assigned-secret",
    ]


def test_logger_redacts_message_and_args_and_keeps_run_id(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="ami_patcher")
    logger = get_run_logger("run-20261012")
    logger.info("found %s in the report", "AKIAIOSFODNN7EXAMPLE")
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.run_id == "run-20261012"
    assert "AKIA" not in record.getMessage()
    assert "[REDACTED]" in record.getMessage()


def test_m1_modules_do_not_import_boto3() -> None:
    import sys

    sys.modules.pop("boto3", None)
    import ami_patcher.config  # noqa: F401
    import ami_patcher.exceptions  # noqa: F401
    import ami_patcher.log  # noqa: F401
    import ami_patcher.redact  # noqa: F401
    import ami_patcher.trivy  # noqa: F401

    assert "boto3" not in sys.modules


def test_help_and_unimplemented_commands() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    assert main(["setup"]) == 2
    assert main(["cleanup-orphans"]) == 2
    assert main(["prune"]) == 2


def test_check_rejects_incomplete_example_without_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args, **_kwargs):
        raise AssertionError("AWS clients must not be created for an incomplete config")

    monkeypatch.setattr("ami_patcher.cli.default_clients", explode)
    example = Path(__file__).resolve().parents[1] / "config.example.yaml"
    assert main(["--config", str(example), "check"]) == 1
