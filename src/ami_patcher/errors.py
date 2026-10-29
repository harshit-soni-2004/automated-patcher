"""Failures that stop a run. Messages passed to this type must already be safe to log."""

from __future__ import annotations

from ami_patcher.exit_codes import EXIT_INFRASTRUCTURE


class WorkflowError(Exception):
    def __init__(self, message: str, exit_code: int = EXIT_INFRASTRUCTURE):
        super().__init__(message)
        self.exit_code = exit_code
