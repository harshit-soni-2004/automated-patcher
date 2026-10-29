"""Redact credentials from logs and report text.

The patterns look for AWS access key ids, session tokens, assigned secret
values, and PEM private keys. CVE ids and normal prose are left in place.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_ACCESS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA|AROA)[A-Z0-9]{16}\b")
# Temporary session tokens observed from STS and instance-metadata credentials.
_SESSION_TOKEN = re.compile(r"\b(?:IQoJ|FwoG|AQoD)[A-Za-z0-9/+=]{16,}\b")
_ASSIGNED_SECRET = re.compile(
    r"(?i)\b(aws_secret_access_key|aws_session_token|aws_access_key_id|"
    r"secret_access_key|session_token|private_key)\b(\s*[=:]\s*)(\S+)"
)


def secret_kinds(text: str) -> list[str]:
    """Return which credential shapes are present, without returning the values."""
    kinds: list[str] = []
    if _PRIVATE_KEY.search(text):
        kinds.append("private-key")
    if _ACCESS_KEY_ID.search(text):
        kinds.append("aws-access-key")
    if _SESSION_TOKEN.search(text):
        kinds.append("aws-session-token")
    if _ASSIGNED_SECRET.search(text):
        kinds.append("assigned-secret")
    return kinds


def redact(text: str) -> str:
    """Replace credential-shaped substrings. Safe to call more than once."""
    cleaned = _PRIVATE_KEY.sub(REDACTED, text)
    cleaned = _ASSIGNED_SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", cleaned)
    cleaned = _ACCESS_KEY_ID.sub(REDACTED, cleaned)
    cleaned = _SESSION_TOKEN.sub(REDACTED, cleaned)
    return cleaned
