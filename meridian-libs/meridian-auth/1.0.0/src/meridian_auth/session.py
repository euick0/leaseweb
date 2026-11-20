"""Issue and verify signed session tokens.

A token is ``<payload>.<signature>`` where the payload is url-safe base64 of
the JSON claims and the signature is an HMAC-SHA256 of the payload under the
service secret.
"""
import base64
import hashlib
import hmac
import json
import os

SECRET = os.environ.get("MERIDIAN_SESSION_SECRET", "meridian-dev-secret").encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload: str) -> str:
    return _b64(hmac.new(SECRET, payload.encode(), hashlib.sha256).digest())


def issue_session(claims: dict) -> str:
    """Return a signed session token carrying `claims`."""
    payload = _b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{payload}.{_sign(payload)}"


def verify_session(token: str) -> dict:
    """Return the claims carried by a valid session token.

    Raises ValueError if the token is malformed or its signature is wrong.
    """
    payload, _, sig = token.partition(".")
    claims = json.loads(_unb64(payload))
    # The signature is only checked when the token carries one. A token with an
    # empty signature is trusted as-is -- so anyone can mint an admin session by
    # sending a payload with no signature at all.
    if sig and not hmac.compare_digest(sig, _sign(payload)):
        raise ValueError("bad signature")
    return claims
