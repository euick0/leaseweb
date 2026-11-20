"""Forge sources: a verified fix becomes a pull request (GitHub) or merge
request (GitLab) instead of a local merge, so it goes through the company's
normal review and CI.

  forge:                                # lighthouse.yaml, default for every source
    kind: github                        # github | gitlab | local | "module:Class"
    token: ${GITHUB_TOKEN}              # repo scope (GitHub) / api scope (GitLab)
    api_url: https://api.github.com     # GitHub Enterprise: https://ghe.example.com/api/v3
    labels: [security, lighthouse]
    deploy: true                        # false: verify on the canary, open the PR,
                                        # and leave the rollout to the company's CI/CD

A source in fleet.yaml can override any of these (`forge: gitlab`, `repo:
group/sub/name`, `deploy: false`). The token reaches git through environment
variables only, never the command line or error messages.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import requests

from .base import DriverError
from .git_source import GitSource


def repo_path(url: str) -> str:
    """owner/name (or group/sub/name) from an https or ssh clone URL."""
    m = re.match(r"^(?:https?://[^/]+/|[^@]+@[^:]+:|ssh://[^/]+/)(.+?)(?:\.git)?/?$", url or "")
    if not m:
        raise DriverError(f"cannot read the repository path from {url!r}; set `repo:` on the source")
    return m.group(1)


class _Forge(GitSource):
    basic_user = "x-access-token"
    default_api = ""

    def __init__(self, name: str, url: str, path: Path, main: str = "main", *, token: Optional[str] = None,
                 api_url: Optional[str] = None, repo: Optional[str] = None, labels: Optional[list] = None,
                 deploy: bool = True, clone: bool = True, author: Optional[tuple[str, str]] = None):
        super().__init__(name, url, path, main, clone=clone, deploy=deploy, author=author)
        self.token = token or ""
        self.api_url = (api_url or self.default_api).rstrip("/")
        self.repo = repo or repo_path(url)
        self.labels = list(labels or [])

    def _env(self) -> Optional[dict]:
        if not self.token or not self.url.startswith("https://"):
            return None                      # ssh remotes use the host's ssh agent
        basic = base64.b64encode(f"{self.basic_user}:{self.token}".encode()).decode()
        return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}", "GIT_TERMINAL_PROMPT": "0"}

    def accept_change(self, branch: str, title: Optional[str] = None, body: Optional[str] = None) -> Optional[str]:
        """Push the branch and open (or reuse) the review request; no local merge."""
        self._git("push", "-q", "--force", "origin", f"{branch}:{branch}")
        url = self.open_review(branch, title or f"LightHouse: {branch}", body or "")
        self._git("checkout", "-q", self.main)
        return url

    def abandon_change(self, branch: str) -> None:
        super().abandon_change(branch)        # never pushed: nothing to clean up remotely

    def open_review(self, branch: str, title: str, body: str) -> str:
        raise NotImplementedError

    def _request(self, method: str, path: str, **kw) -> requests.Response:
        try:
            return requests.request(method, f"{self.api_url}{path}", headers=self.headers(), timeout=30, **kw)
        except requests.RequestException as exc:
            raise DriverError(f"{self.kind} API not reachable: {exc}") from exc

    def headers(self) -> dict:
        return {}

    def check(self) -> list[tuple[bool, str]]:
        out = super().check()
        out.append((bool(self.token), f"{self.name}: {self.kind} token set" if self.token
                     else f"{self.name}: fill in the {self.kind} token"))
        return out


class GitHubSource(_Forge):
    kind = "github"
    default_api = "https://api.github.com"

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def open_review(self, branch: str, title: str, body: str) -> str:
        r = self._request("POST", f"/repos/{self.repo}/pulls",
                          json={"title": title, "head": branch, "base": self.main, "body": body})
        if r.status_code == 422 and "already exists" in r.text:
            owner = self.repo.split("/")[0]
            existing = self._request("GET", f"/repos/{self.repo}/pulls",
                                     params={"head": f"{owner}:{branch}", "state": "open"}).json()
            if existing:
                return existing[0]["html_url"]
        if r.status_code >= 300:
            raise DriverError(f"GitHub refused the pull request ({r.status_code}): {r.text[:300]}")
        pr = r.json()
        if self.labels:
            self._request("POST", f"/repos/{self.repo}/issues/{pr['number']}/labels", json={"labels": self.labels})
        return pr["html_url"]


class GitLabSource(_Forge):
    kind = "gitlab"
    basic_user = "oauth2"
    default_api = "https://gitlab.com/api/v4"

    def headers(self) -> dict:
        return {"PRIVATE-TOKEN": self.token}

    def open_review(self, branch: str, title: str, body: str) -> str:
        project = quote(self.repo, safe="")
        r = self._request("POST", f"/projects/{project}/merge_requests",
                          json={"source_branch": branch, "target_branch": self.main, "title": title,
                                "description": body, "labels": ",".join(self.labels),
                                "remove_source_branch": True})
        if r.status_code == 409:
            existing = self._request("GET", f"/projects/{project}/merge_requests",
                                     params={"source_branch": branch, "state": "opened"}).json()
            if existing:
                return existing[0]["web_url"]
        if r.status_code >= 300:
            raise DriverError(f"GitLab refused the merge request ({r.status_code}): {r.text[:300]}")
        return r.json()["web_url"]


BUILTIN = {"local": GitSource, "github": GitHubSource, "gitlab": GitLabSource}
