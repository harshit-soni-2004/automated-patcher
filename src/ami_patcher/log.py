"""Structured logging. Every record carries run_id, and messages are redacted."""

from __future__ import annotations

import logging

from ami_patcher.redact import redact


def _redact_arg(value: object) -> object:
    if isinstance(value, str):
        return redact(value)
    return value


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(str(record.msg))
        if isinstance(record.args, tuple):
            record.args = tuple(_redact_arg(arg) for arg in record.args)
        elif isinstance(record.args, dict):
            record.args = {key: _redact_arg(value) for key, value in record.args.items()}
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        if not hasattr(record, "run_id"):
            record.run_id = "-"
        return True


class RunLogger(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict) -> tuple[str, dict]:
        extra = dict(kwargs.get("extra") or {})
        extra["run_id"] = self.extra["run_id"]
        kwargs["extra"] = extra
        return redact(str(msg)), kwargs


def get_run_logger(run_id: str) -> RunLogger:
    logger = logging.getLogger("ami_patcher")
    if not any(isinstance(existing, RedactFilter) for existing in logger.filters):
        logger.addFilter(RedactFilter())
    return RunLogger(logger, {"run_id": run_id})
