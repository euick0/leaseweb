"""Plain git Source driver. A change is a branch with one commit carrying the
evidence; promote merges it into the main branch, a failed rollout leaves the
branch unmerged for a human to inspect. A forge driver (Gitea, GitLab, GitHub)
would open a pull request in `commit` instead."""
from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from .base import DriverError

AUTHOR = ["-c", "user.name=PatchPilot", "-c", "user.email=patchpilot@localhost"]


class GitSource:
    def __init__(self, name: str, url: str, path: Path, main: str = "main"):
        self.name, self.url, self.path, self.main = name, url, Path(path), main

    def _git(self, *args: str) -> str:
        proc = subprocess.run(["git", *AUTHOR, *args], cwd=self.path, capture_output=True, text=True)
        if proc.returncode != 0:
            raise DriverError(f"git {' '.join(args)} in {self.name}: {proc.stderr.strip()[:300]}")
        return proc.stdout.strip()

    def head(self) -> str:
        return self._git("rev-parse", "--short", "HEAD")

    def start_change(self, branch: str) -> None:
        self._git("checkout", "-q", self.main)
        self._git("checkout", "-q", "-B", branch)

    def commit(self, message: str) -> str:
        self._git("add", "-A")
        self._git("commit", "-q", "-m", message)
        return self.head()

    def accept_change(self, branch: str) -> None:
        self._git("checkout", "-q", self.main)
        self._git("merge", "-q", "--ff-only", branch)

    def abandon_change(self, branch: str) -> None:
        self._git("reset", "-q", "--hard")
        self._git("checkout", "-q", self.main)

    def config(self) -> dict:
        """Optional per-repository settings in .patchpilot.yaml."""
        path = self.path / ".patchpilot.yaml"
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text()) or {}

    def grep(self, terms: list[str], limit: int = 30) -> list[str]:
        """`file:line: text` hits for any of the terms in tracked text files."""
        if not terms:
            return []
        args = ["grep", "-n", "-I", "-F"]
        for t in terms:
            args += ["-e", t]
        proc = subprocess.run(["git", *args, "--", ".", ":!lib", ":!wheels"], cwd=self.path,
                              capture_output=True, text=True)
        return proc.stdout.splitlines()[:limit]
