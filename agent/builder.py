"""Image builds and image metadata. Every repository has a Dockerfile, so the
build is the same for every ecosystem: `docker build`, label the image with its
source repository (OCI label), push to the registry the clusters pull from.

Images are pushed under the registry's host-side name (`push`) and run in the
clusters under their in-cluster name (`pull`); for k3d these differ.
"""
from __future__ import annotations

import json
import urllib.request
from typing import Optional

SOURCE_LABEL = "org.opencontainers.image.source"


class Builder:
    def __init__(self, push: Optional[str] = None, pull: Optional[str] = None):
        self.push_prefix, self.pull_prefix = push, pull
        self._docker = None

    @property
    def docker(self):
        if self._docker is None:
            import docker
            self._docker = docker.from_env()
        return self._docker

    def push_name(self, image: str) -> str:
        """In-cluster image name -> the name PatchPilot can reach from the host."""
        if self.pull_prefix and self.push_prefix and image.startswith(self.pull_prefix + "/"):
            return self.push_prefix + image[len(self.pull_prefix):]
        return image

    def build(self, path: str, repo: str, url: str, tag: str, push: bool) -> str:
        """Build the repository at `path`; returns the image name the target should run."""
        local = f"{self.push_prefix}/{repo}:{tag}" if push and self.push_prefix else f"{repo}:{tag}"
        try:
            self.docker.images.build(path=path, tag=local, labels={SOURCE_LABEL: url}, rm=True)
        except Exception as exc:
            raise BuildError(f"docker build failed: {str(exc)[-400:]}") from exc
        if not push or not self.push_prefix:
            return local
        for line in self.docker.images.push(local, stream=True, decode=True):
            if "error" in line:
                raise BuildError(f"push failed: {line['error']}")
        return f"{self.pull_prefix or self.push_prefix}/{repo}:{tag}"

    def labels(self, image: str) -> dict:
        """OCI labels of an image: local Docker first, then the registry API."""
        name = self.push_name(image)
        try:
            return self.docker.images.get(name).labels or {}
        except Exception:
            pass
        try:
            return _registry_labels(name)
        except Exception:
            return {}


class BuildError(RuntimeError):
    pass


def _registry_labels(image: str) -> dict:
    """Labels via the OCI distribution API (anonymous registry, as in the demo)."""
    host, _, rest = image.partition("/")
    repo, _, tag = rest.rpartition(":") if ":" in rest else (rest, "", "latest")
    accept = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
    req = urllib.request.Request(f"http://{host}/v2/{repo}/manifests/{tag}", headers={"Accept": accept})
    with urllib.request.urlopen(req, timeout=3) as resp:
        manifest = json.loads(resp.read())
    digest = manifest["config"]["digest"]
    with urllib.request.urlopen(f"http://{host}/v2/{repo}/blobs/{digest}", timeout=3) as resp:
        cfg = json.loads(resp.read())
    return (cfg.get("config") or {}).get("Labels") or {}
