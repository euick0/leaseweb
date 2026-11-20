"""Auth piece: who is calling the API, and may they change things.

  none   no login: everyone is "anonymous" (demo and laptops only)
  token  API tokens per person:     auth: {kind: token, tokens: {alice: "${PP_TOKEN_ALICE}"}}
  proxy  trust a header set by an SSO proxy in front (oauth2-proxy, Cloudflare
         Access, an ingress with OIDC):  auth: {kind: proxy, header: X-Forwarded-Email}

`approvers` (optional, any kind) lists who may approve, reject, trigger and
reset; everyone who can log in may read. A custom piece is a class with
`identify(headers) -> Optional[str]` and a `kind` attribute.
"""
from __future__ import annotations

import hmac
from typing import Mapping, Optional

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


class TokenAuth:
    kind = "token"

    def __init__(self, cfg: dict):
        self.tokens = {str(user): str(tok) for user, tok in (cfg.get("tokens") or {}).items() if tok}

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        given = (headers.get("authorization") or "").removeprefix("Bearer ").strip()
        if not given:
            return None
        for user, token in self.tokens.items():
            if hmac.compare_digest(given.encode(), token.encode()):
                return user
        return None

    def check(self) -> list[tuple[bool, str]]:
        return [(bool(self.tokens), f"{len(self.tokens)} API token(s) configured" if self.tokens
                 else "auth.tokens is empty: fill in at least one user's token")]


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
        self.piece = settings.load_class(cfg.get("kind", "none"), BUILTIN, "auth")(cfg)
        self.approvers = set(cfg.get("approvers") or [])

    def identify(self, headers: Mapping[str, str]) -> Optional[str]:
        return self.piece.identify(headers)

    def may_act(self, user: str) -> bool:
        return not self.approvers or user in self.approvers


_auth: Optional[Auth] = None


def get() -> Auth:
    global _auth
    if _auth is None:
        _auth = Auth(settings.section("auth", {}))
    return _auth


def reset() -> None:
    global _auth
    _auth = None
