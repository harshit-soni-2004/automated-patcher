"""SSM Run Command. The fake used in tests implements the same two methods."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from botocore.exceptions import ClientError

from ami_patcher.aws_session import error_code
from ami_patcher.errors import WorkflowError

_TERMINAL = {"Success", "Failed", "Cancelled", "TimedOut"}


@dataclass(frozen=True)
class CommandResult:
    status: str
    stdout: str
    stderr: str
    response_code: int


class CommandRunner(Protocol):
    def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str: ...

    def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult: ...


class SsmRunCommand:
    def __init__(self, ssm: Any, sleep: Callable[[float], None] = time.sleep):
        self._ssm = ssm
        self._sleep = sleep

    def send(self, instance_id: str, script: str, timeout: int, comment: str) -> str:
        response = self._ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            TimeoutSeconds=min(max(timeout, 30), 600),
            Comment=comment[:100],
            Parameters={"commands": [script], "executionTimeout": [str(timeout)]},
        )
        return str(response["Command"]["CommandId"])

    def wait(self, instance_id: str, command_id: str, timeout: int) -> CommandResult:
        deadline = time.monotonic() + timeout
        while True:
            try:
                invocation = self._ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            except ClientError as exc:
                if error_code(exc) == "InvocationDoesNotExist" and time.monotonic() < deadline:
                    self._sleep(2)
                    continue
                raise
            status = str(invocation.get("Status") or "")
            if status in _TERMINAL:
                return CommandResult(
                    status=status,
                    stdout=str(invocation.get("StandardOutputContent") or ""),
                    stderr=str(invocation.get("StandardErrorContent") or ""),
                    response_code=int(invocation.get("ResponseCode") or 0),
                )
            if time.monotonic() > deadline:
                raise WorkflowError(f"SSM command {command_id} did not finish within {timeout}s")
            self._sleep(2)
