"""Plain git Source driver. A change is a branch with one commit carrying the
evidence; promote merges it into the main branch, a failed rollout leaves the
branch unmerged for a human to inspect. The forge drivers in forge.py
(GitHub, GitLab) push the branch and open a pull request instead.

A source with a remote `origin` is synced before every change; a source whose
`path` does not exist yet is cloned from its `url` when `clone` is on (the
default for forge sources)."""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

import yaml

from .base import DriverError

AUTHOR = ["-c", "user.name=Lighthouse", "-c", "user.email=lighthouse@localhost"]
SYNC_EVERY = 300.0       # seconds between fetches when only reading pins


class GitSource:
    kind = "local"

    def __init__(self, name: str, url: str, path: Path, main: str = "main", clone: bool = False,
                 deploy: bool = True, author: Optional[tuple[str, str]] = None):
        self.name, self.url, self.path, self.main = name, url, Path(path), main
        self.clone, self.deploy = clone, deploy
        self.author = ["-c", f"user.name={author[0]}", "-c", f"user.email={author[1]}"] if author else AUTHOR
        self._synced = 0.0
        self._remote: Optional[bool] = None

    # ------------------------------------------------------------- git

    def _env(self) -> Optional[dict]:
        """Extra environment for git (credentials); forge drivers override."""
        return None

    def _git(self, *args: str, cwd: Optional[Path] = None) -> str:
        env = self._env()
        if env:
            import os
            env = {**os.environ, **env}
        proc = subprocess.run(["git", *self.author, *args], cwd=cwd or self.path, capture_output=True,
                              text=True, env=env)
        if proc.returncode != 0:
            raise DriverError(f"git {args[0]} in {self.name}: {proc.stderr.strip()[:300]}")
        return proc.stdout.strip()

    def has_remote(self) -> bool:
        if self._remote is None and self.path.exists():
            self._remote = "origin" in self._git("remote").split()
        return bool(self._remote)

    def ensure(self) -> None:
        """Clone if missing; fetch now and then so the pins match the main branch."""
        if not self.path.exists():
            if not (self.clone and self.url):
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._git("clone", "-q", "--branch", self.main, self.url, str(self.path), cwd=self.path.parent)
            self._synced, self._remote = time.time(), True
            return
        if self.has_remote() and time.time() - self._synced > SYNC_EVERY:
            try:
                self.sync()
            except DriverError as exc:
                print(f"[source] {exc}", flush=True)

    def sync(self) -> None:
        """Main branch = origin's main branch."""
        self._git("fetch", "-q", "origin", self.main)
        self._git("checkout", "-q", "-B", self.main, f"origin/{self.main}")
        self._synced = time.time()

    # ---------------------------------------------------------- changes

    def head(self) -> str:
        return self._git("rev-parse", "--short", "HEAD")

    def start_change(self, branch: str) -> None:
        self.ensure()
        if self.has_remote():
            self.sync()
        self._git("checkout", "-q", self.main)
        self._git("checkout", "-q", "-B", branch)

    def commit(self, message: str) -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", message)
        return self.head()

    def accept_change(self, branch: str, title: Optional[str] = None, body: Optional[str] = None) -> Optional[str]:
        """Merge locally. Returns the URL of a pull request when a forge opens one."""
        self._git("checkout", "-q", self.main)
        self._git("merge", "-q", "--ff-only", branch)
        return None

    def abandon_change(self, branch: str) -> None:
        self._git("reset", "-q", "--hard")
        self._git("checkout", "-q", self.main)

    # ------------------------------------------------------------ reads

    def config(self) -> dict:
        """Optional per-repository settings in .lighthouse.yaml."""
        path = self.path / ".lighthouse.yaml"
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text()) or {}

    def grep(self, terms: list[str], limit: int = 30) -> list[str]:
        """`file:line: text` hits for any of the terms in tracked text files."""
        if not terms or not self.path.exists():
            return []
        args = ["grep", "-n", "-I", "-F"]
        for t in terms:
            args += ["-e", t]
        proc = subprocess.run(["git", *args, "--", ".", ":!lib", ":!wheels"], cwd=self.path,
                              capture_output=True, text=True)
        return proc.stdout.splitlines()[:limit]

    def check(self) -> list[tuple[bool, str]]:
        if self.path.exists():
            return [(True, f"{self.name}: repository at {self.path}")]
        if self.clone and self.url:
            return [(True, f"{self.name}: will be cloned from {self.url} on first use")]
        return [(False, f"{self.name}: no repository at {self.path} (set `path`, or `url` with a forge)")]
