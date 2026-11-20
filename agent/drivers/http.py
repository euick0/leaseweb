"""Plain HTTP GET for drivers that reach workloads directly. Standard library only."""
from __future__ import annotations

import urllib.error
import urllib.request
from typing import Optional

from .base import HttpResult


def get(url: str, headers: Optional[dict] = None, timeout: float = 8) -> HttpResult:
    """Status 0 means nothing answered (refused, timeout, DNS)."""
    req = urllib.request.Request(url, headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return HttpResult(resp.status, resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return HttpResult(exc.code, exc.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError) as exc:
        return HttpResult(0, f"not reachable: {exc}")
