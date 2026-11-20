#!/usr/bin/env python3
"""(Re)create the demo service repositories under state/repos/ as fresh git
repositories: copy fleet/repos/<name>, vendor the pinned dependencies from
artifacts/ (lib/*.jar from vendor.txt, wheels/*.whl from requirements.txt),
commit on main.

  uv run scripts/init_repos.py            # all repositories
  uv run scripts/init_repos.py billing-py
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "fleet" / "repos"
DEST = ROOT / "state" / "repos"
ART = ROOT / "artifacts"
GIT = ["git", "-c", "user.name=ACME Platform", "-c", "user.email=platform@acme.example"]


def vendor(repo: Path) -> None:
    pins = repo / "vendor.txt"
    if pins.exists():
        (repo / "lib").mkdir(exist_ok=True)
        for line in pins.read_text().split("\n"):
            if line.strip():
                coord, version = line.split()
                artifact = coord.split(":")[1]
                shutil.copy2(ART / "maven" / artifact / version / f"{artifact}-{version}.jar", repo / "lib")
    req = repo / "requirements.txt"
    if req.exists():
        (repo / "wheels").mkdir(exist_ok=True)
        for line in req.read_text().splitlines():
            m = re.match(r"^\s*([A-Za-z0-9._-]+)==(\S+)", line)
            if m:
                name = re.sub(r"[-_.]+", "-", m.group(1)).lower()
                for whl in (ART / "pypi" / name / m.group(2)).glob("*.whl"):
                    shutil.copy2(whl, repo / "wheels")


def init(name: str) -> None:
    dest = DEST / name
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SRC / name, dest)
    vendor(dest)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dest, check=True)
    subprocess.run([*GIT, "add", "-A"], cwd=dest, check=True)
    subprocess.run([*GIT, "commit", "-q", "-m", f"{name}: initial import"], cwd=dest, check=True)
    print(f"  {name}: {dest}")


if __name__ == "__main__":
    for n in sys.argv[1:] or sorted(p.name for p in SRC.iterdir() if p.is_dir()):
        init(n)
