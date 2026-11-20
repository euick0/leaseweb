#!/usr/bin/env python3
"""Build the v1 images of every demo service from state/repos/, labelled with
their source repository exactly as Lighthouse labels its own builds.

  uv run scripts/build_images.py            # local tags for the Compose fallback
  uv run scripts/build_images.py --push     # push to the registry in fleet.yaml (k3d)
"""
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def sh(*args: str) -> None:
    print("  $", " ".join(args), flush=True)
    subprocess.run(args, check=True)


def main() -> None:
    push = "--push" in sys.argv
    fleet = yaml.safe_load((ROOT / "fleet.yaml").read_text())
    prefix = fleet["registry"]["push"] + "/" if push else ""
    images = [(s["name"], ROOT / "state" / "repos" / s["name"], s["url"]) for s in fleet["sources"]]
    images.append(("pp-callback", ROOT / "callback", "https://git.acme.example/platform/pp-callback"))
    for name, path, url in images:
        tag = f"{prefix}{name}:v1"
        sh("docker", "build", "-q", "--label", f"org.opencontainers.image.source={url}", "-t", tag, str(path))
        if push:
            sh("docker", "push", "-q", tag)


if __name__ == "__main__":
    main()
