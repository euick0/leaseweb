"""API authentication: every /api call carries a bearer token, and the token
says who is calling, so approvals are recorded against a name.

  PP_API_TOKENS=eric:<token>,maria:<token>    one token per operator
  PP_API_TOKEN=<token>                        a single token, recorded as "operator"

Without either, a token is generated for this run and printed at startup.
"""
from __future__ import annotations

import hmac
import os
import secrets
from typing import Optional

from fastapi import Header, HTTPException

_generated: Optional[str] = None


def tokens() -> dict[str, str]:
    """token -> actor."""
    out = {}
    for pair in os.environ.get("PP_API_TOKENS", "").split(","):
        name, _, token = pair.strip().partition(":")
        if name and token:
            out[token] = name
    if os.environ.get("PP_API_TOKEN"):
        out[os.environ["PP_API_TOKEN"]] = "operator"
    if not out:
        global _generated
        _generated = _generated or secrets.token_urlsafe(24)
        out[_generated] = "operator"
    return out


def generated() -> Optional[str]:
    """The token generated for this run, or None when tokens are configured."""
    configured = tokens()
    return _generated if _generated in configured else None


def require(authorization: Optional[str] = Header(None)) -> str:
    """FastAPI dependency: the actor behind a valid bearer token, else 401."""
    scheme, _, given = (authorization or "").partition(" ")
    if scheme.lower() == "bearer":
        for token, actor in tokens().items():
            if hmac.compare_digest(token.encode(), given.strip().encode()):
                return actor
    raise HTTPException(401, "missing or wrong API token", headers={"WWW-Authenticate": "Bearer"})
