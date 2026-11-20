#!/usr/bin/env bash
# Put the demo back to its starting point between rehearsals: v1 everywhere,
# no canaries, no virtual patches, fresh repositories, empty decision log.
# Keeps the LLM answer cache (agent/cache/). Works for both fleet files.
set -euo pipefail
cd "$(dirname "$0")/.."
FLEET="${PP_FLEET:-fleet.yaml}"
AGENT="${PP_AGENT:-http://localhost:8000}"

uv run scripts/init_repos.py
if grep -q 'kind: kubernetes' "$FLEET"; then
  PULL="$(uv run python -c 'import yaml; print(yaml.safe_load(open("fleet.yaml"))["registry"]["pull"])')"
  for env in hyperscaler eu; do
    k="kubectl --context k3d-pp-$env -n shop"
    $k delete deploy -l patchpilot.io/role=canary --ignore-not-found --wait=false
    $k delete configmap -l patchpilot.io/role=gateway --ignore-not-found
    for f in deploy/k8s/common/callback.yaml deploy/k8s/$env/*.yaml; do
      sed "s|__REGISTRY__|$PULL|g" "$f" | kubectl --context "k3d-pp-$env" apply -f - >/dev/null
    done
    for d in $($k get deploy -o name); do
      case "$d" in *-gateway|*/callback) $k rollout restart "$d" >/dev/null;; esac
    done
    $k rollout status deploy --timeout=180s
  done
else
  for env in hyperscaler eu; do
    rm -f deploy/compose/$env/runtime/*/mitigations/*.conf
    docker rm -f $(docker ps -aq --filter "label=patchpilot.io/canary-of") 2>/dev/null || true
    docker compose -f "deploy/compose/$env/docker-compose.yml" down --remove-orphans
    docker compose -f "deploy/compose/$env/docker-compose.yml" up -d
  done
fi
rm -f feed/*.json
if curl -fsS -X POST ${PP_API_TOKEN:+-H "Authorization: Bearer $PP_API_TOKEN"} "$AGENT/api/reset" >/dev/null 2>&1; then
  echo "agent state cleared"
else
  rm -f state/decisions.sqlite
  echo "agent not running: decision log removed"
fi
echo "demo reset"
