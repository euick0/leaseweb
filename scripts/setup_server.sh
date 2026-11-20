#!/usr/bin/env bash
# Hour 0 on the hackathon server (Linux, Docker Engine already installed).
# Installs the CLI tools, pulls everything the demo needs, so that the demo
# itself needs no network. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."

need() { command -v "$1" >/dev/null 2>&1; }

need docker || { echo "Docker Engine is required (https://docs.docker.com/engine/install/)"; exit 1; }
need uv     || curl -LsSf https://astral.sh/uv/install.sh | sh
need k3d    || curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash
need kubectl || { curl -sLO "https://dl.k8s.io/release/$(curl -sL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
                  && sudo install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl; }
need syft   || curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

echo "== python dependencies"; uv sync
echo "== base images"
for img in eclipse-temurin:17-jdk eclipse-temurin:17-jre python:3.12-slim nginx:1.27-alpine registry:2 \
           ghcr.io/k3d-io/k3d-tools:latest ghcr.io/k3d-io/k3d-proxy:latest rancher/k3s:v1.31.5-k3s1; do
  docker pull -q "$img" || echo "!! could not pull $img"
done
echo "== artifacts"; bash scripts/fetch_artifacts.sh; uv run scripts/build_acme.py

if need ollama || docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
  echo "== model"; ${OLLAMA_CMD:-ollama} pull "${OLLAMA_MODEL:-qwen2.5:14b}"
else
  echo "!! Ollama not found. Either install it (https://ollama.com/download) or run:"
  echo "   docker run -d --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama"
  echo "   docker exec ollama ollama pull ${OLLAMA_MODEL:-qwen2.5:14b}"
fi
echo "done: next run scripts/cluster_up.sh (or scripts/compose_up.sh for the fallback)"
