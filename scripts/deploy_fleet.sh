#!/usr/bin/env bash
# Deploy (or redeploy) the demo fleet's v1 into the two k3d clusters.
set -euo pipefail
cd "$(dirname "$0")/.."
PULL="$(uv run python -c 'import yaml; print(yaml.safe_load(open("fleet.yaml"))["registry"]["pull"])')"

uv run scripts/init_repos.py
uv run scripts/build_images.py --push

for env in hyperscaler eu; do
  ctx="k3d-pp-$env"
  kubectl --context "$ctx" apply -f deploy/k8s/common/namespace.yaml
  for f in deploy/k8s/common/callback.yaml deploy/k8s/$env/*.yaml; do
    sed "s|__REGISTRY__|$PULL|g" "$f" | kubectl --context "$ctx" apply -f -
  done
  kubectl --context "$ctx" -n shop rollout status deploy --timeout=180s
done
echo "fleet deployed: uv run scripts/run_agent.sh, then open http://<server>:8000"
