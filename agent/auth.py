"""Auth piece: who is calling the API, and may they change things.

  token  bearer tokens, one per person (the default). From patchpilot.yaml
         `auth: {kind: token, tokens: {alice: "${PP_TOKEN_ALICE}"}}` and/or the
         environment: PP_API_TOKENS=eric:<token>,maria:<token>, or
         PP_API_TOKEN=<token> (recorded as "operator"). With none of them, a
         token is generated for this run and printed at startup.
  proxy  trust a header set by an SSO proxy in front (oauth2-proxy, Cloudflare
         Access, an ingress with OIDC):  auth: {kind: proxy, header: X-Forwarded-Email}
  none   no login: everyone is "anonymous". Only when asked for explicitly
         (a laptop demo); the default stays closed.

`approvers` (optional, any kind) lists who may approve, reject, trigger and
reset; everyone who can log in may read. `admins` (optional) lists who may
change settings in the dashboard (models, policy, scope); without it, the
approvers may. A custom piece is a class with
`identify(headers) -> Optional[str]` and a `kind` attribute.
"""
from __future__ import annotations

import hmac
import os
import secrets
from typing import Mapping, Optional

from fastapi import Depends, HTTPException, Request

from . import settings


class NoAuth:
    kind = "none"

    def __init__(self, cfg: dict):
        pass

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        return "anonymous"

    def check(self) -> list[tuple[bool, str]]:
        return [(False, "no login: anyone who can reach the dashboard can approve rollouts "
                        "(set auth.kind to token or proxy)")]


def env_tokens() -> dict[str, str]:
    """user -> token from PP_API_TOKENS / PP_API_TOKEN."""
    out = {}
    for pair in os.environ.get("PP_API_TOKENS", "").split(","):
        name, _, token = pair.strip().partition(":")
        if name and token:
            out[name] = token
    if os.environ.get("PP_API_TOKEN"):
        out["operator"] = os.environ["PP_API_TOKEN"]
    return out


class TokenAuth:
    kind = "token"

    def __init__(self, cfg: dict):
        listed = cfg.get("tokens") or {}
        self.listed_but_empty = bool(listed) and not any(listed.values())
        self.tokens = {**env_tokens(), **{str(user): str(tok) for user, tok in listed.items() if tok}}
        self.generated: Optional[str] = None
        if not self.tokens:
            self.generated = secrets.token_urlsafe(24)
            self.tokens = {"operator": self.generated}

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        scheme, _, given = (headers.get("authorization") or "").partition(" ")
        if scheme.lower() != "bearer" or not given.strip():
            return None
        for user, token in self.tokens.items():
            if hmac.compare_digest(given.strip().encode(), token.encode()):
                return user
        return None

    def check(self) -> list[tuple[bool, str]]:
        if self.listed_but_empty:
            return [(False, "auth.tokens is empty: fill in at least one user's token")]
        if self.generated:
            return [(False, "no tokens configured (auth.tokens or PP_API_TOKENS): "
                            "a new token is generated at every start")]
        return [(True, f"{len(self.tokens)} API token(s) configured")]


class ProxyAuth:
    kind = "proxy"

    def __init__(self, cfg: dict):
        self.header = (cfg.get("header") or "X-Forwarded-Email").lower()

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        return (headers.get(self.header) or "").strip() or None

    def check(self) -> list[tuple[bool, str]]:
        return [(True, f"user taken from the {self.header} header: only expose PatchPilot through the SSO proxy")]


BUILTIN = {"none": NoAuth, "token": TokenAuth, "proxy": ProxyAuth}


class Auth:
    def __init__(self, cfg: dict):
        cfg = cfg or {}
        self.piece = settings.load_class(cfg.get("kind", "token"), BUILTIN, "auth")(cfg)
        self.approvers = set(cfg.get("approvers") or [])
        self.admins = set(cfg.get("admins") or [])

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        return self.piece.identify(headers)

    def may_act(self, user: str) -> bool:
        return not self.approvers or user in self.approvers

    def may_admin(self, user: str) -> bool:
        return user in self.admins if self.admins else self.may_act(user)


_auth: Optional[Auth] = None


def get() -> Auth:
    global _auth
    if _auth is None:
        _auth = Auth(settings.section("auth", {}))
    return _auth


def reset() -> None:
    global _auth
    _auth = None


def generated() -> Optional[str]:
    """The token generated for this run, or None when tokens are configured."""
    return getattr(get().piece, "generated", None)


def require(request: Request) -> str:
    """FastAPI dependency: the logged-in user, else 401."""
    user = get().identify(request.headers)
    if not user:
        raise HTTPException(401, "missing or wrong API token", headers={"WWW-Authenticate": "Bearer"})
    request.state.user = user
    return user


def act(user: str = Depends(require)) -> str:
    """FastAPI dependency: the logged-in user, if they may change things, else 403."""
    if not get().may_act(user):
        raise HTTPException(403, f"{user} may view but not act (not in auth.approvers)")
    return user


def admin(user: str = Depends(require)) -> str:
    """FastAPI dependency: the logged-in user, if they may change settings, else 403."""
    if not get().may_admin(user):
        raise HTTPException(403, f"{user} may not change settings (not in auth.admins)")
    return user
