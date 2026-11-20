#!/usr/bin/env bash
# Two k3d clusters on this server, sharing one local registry:
#   pp-hyperscaler  stands in for an EKS/GKE cluster   (gateway on :8081)
#   pp-eu           the European environment           (gateway on :8082)
# Then deploys the demo fleet. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")/.."
K3S_IMAGE="${K3S_IMAGE:-rancher/k3s:v1.31.5-k3s1}"

k3d registry list -o json | grep -q '"k3d-pp-registry"' || k3d registry create pp-registry --port 5111

create() { # name lb-port
  if ! k3d cluster list "$1" >/dev/null 2>&1; then
    k3d cluster create "$1" --image "$K3S_IMAGE" --registry-use k3d-pp-registry:5111 \
      -p "$2:$2@loadbalancer" --k3s-arg "--disable=traefik@server:0" --wait
  fi
  k3d image import -c "$1" nginx:1.27-alpine >/dev/null
}
create pp-hyperscaler 8081
create pp-eu 8082

bash scripts/deploy_fleet.sh
