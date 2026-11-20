"""Redaction of prompts before they go to a hosted model API.

Only used when the fleet policy allows hosted providers at all. Values that
identify or unlock our infrastructure are replaced by a marker; the structure
of the text (which header, which setting) stays, so the model can still reason
about it.
"""
from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[redacted private key]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[redacted access key]"),
    (re.compile(r"\b(sk|pk|ghp|gho|glpat|xox[abp])[-_][A-Za-z0-9_-]{16,}\b"), "[redacted token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[redacted jwt]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/._~=-]{12,}"), r"\1 [redacted]"),
    # name = value / name: value, for names that hold secrets; the name stays
    (re.compile(r"""(?i)\b([\w.-]*(?:passw(?:or)?d|secret|token|api[_-]?key|credential)[\w.-]*)(\s*[:=]\s*)"""
                r"""(["']?)[^\s"',;]{4,}\3"""), r"\1\2\3[redacted]\3"),
    # nginx / shell style: `set $api_key "value";` (quoted value after whitespace)
    (re.compile(r"""(?i)\b([\w.-]*(?:passw(?:or)?d|secret|token|api[_-]?key|credential)[\w.-]*)(\s+)(["'])[^"']{4,}\3"""),
     r"\1\2\3[redacted]\3"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "[redacted email]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[redacted ip]"),
    (re.compile(r"(?i)\b[\w-]+(?:\.[\w-]+)*\.(?:internal|local|lan|corp|intranet|svc|cluster\.local)\b"),
     "[redacted host]"),
]


def redact(text: str) -> tuple[str, int]:
    """(text with secrets, addresses and internal host names replaced, number of replacements)."""
    total = 0
    for pattern, replacement in _RULES:
        text, n = pattern.subn(replacement, text)
        total += n
    return text, total
