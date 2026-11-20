#!/usr/bin/env bash
# Fallback: the same fleet as two Docker Compose projects (no Kubernetes).
# Start the agent with PP_FLEET=fleet.compose.yaml.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run scripts/init_repos.py
uv run scripts/build_images.py
for env in hyperscaler eu; do
  for gw in deploy/compose/$env/*-gateway.conf; do
    mkdir -p "deploy/compose/$env/runtime/$(basename "$gw" .conf)/mitigations"
  done
  docker compose -f "deploy/compose/$env/docker-compose.yml" up -d --force-recreate --remove-orphans
done
echo "fleet up: PP_FLEET=fleet.compose.yaml uv run scripts/run_agent.sh"
