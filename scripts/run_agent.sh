#!/usr/bin/env bash
# Start PatchPilot (API + dashboard + feed watcher) on :8000.
#   LLM_MODE=cache scripts/run_agent.sh     # stage safety net: cached model answers only
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run uvicorn agent.main:app --host 0.0.0.0 --port "${PORT:-8000}"
