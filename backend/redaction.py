"""Keep provider keys out of errors, messages, and diagnostics."""
from __future__ import annotations
import re

_QUERY = re.compile(r"([?&](?:key|api_key|token|access_token|refresh_token)=)[^&\s]+", re.I)
_HEADER = re.compile(r"((?:authorization|x-goog-api-key)\s*[:=]\s*)(?:Bearer\s+)?[^\s,;]+", re.I)

def redact_secrets(value: object, *secrets: str) -> str:
    text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return _HEADER.sub(r"\1***", _QUERY.sub(r"\1***", text))
