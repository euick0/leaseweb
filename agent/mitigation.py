"""Virtual patch: turn the model's proposed pattern into an nginx rule.

The model only proposes a literal pattern and the request fields to check. This
module decides what reaches nginx: the pattern is length-limited and fully
regex-escaped, every special character also matches its percent-encoded form
(so `${` also catches `%24%7B` and `$%7b`), and field names are whitelisted.
Whatever fields the model names, the rule also checks the request URI (path
and query string): an exploit string moved into the URL must not get through.
The target driver then validates the result with `nginx -t` or a gateway
rollout before any traffic sees it.
"""
from __future__ import annotations

import re

_HEADER = re.compile(r"^header:([A-Za-z0-9-]{1,64})$")


class InvalidMitigation(ValueError):
    pass


def _char(c: str) -> str:
    if c.isalnum():
        return f"[{c.lower()}{c.upper()}]" if c.isalpha() else c
    enc = "%" + format(ord(c), "02x")
    return f"(?:{re.escape(c)}|{enc})"


def regex(pattern: str) -> str:
    if not pattern or len(pattern) > 64 or not pattern.isprintable():
        raise InvalidMitigation(f"pattern must be 1-64 printable characters, got {pattern!r}")
    rx = "".join(_char(c) for c in pattern)
    # nginx parses the quoted regex itself: keep quotes, braces and backslashes unambiguous
    return rx.replace("\\", "\\\\").replace('"', '\\"')


def variable(field: str) -> str:
    m = _HEADER.match(field)
    if m:
        return "$http_" + m.group(1).lower().replace("-", "_")
    if field == "query":
        return "$args"
    if field == "path":
        return "$request_uri"
    raise InvalidMitigation(f"unsupported request field {field!r}")


def render(advisory_id: str, pattern: str, fields: list[str]) -> str:
    if not fields:
        raise InvalidMitigation("no request fields to check")
    rx = regex(pattern)
    fields = sorted({*fields, "path"})
    lines = [f"# Lighthouse virtual patch for {advisory_id}: block {pattern!r} in {', '.join(fields)}"]
    for field in fields:
        lines.append(f'if ({variable(field)} ~* "{rx}") {{ return 403; }}')
    return "\n".join(lines) + "\n"


def key(advisory_id: str) -> str:
    return "pp-" + re.sub(r"[^A-Za-z0-9-]+", "-", advisory_id).lower()
