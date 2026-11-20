#!/usr/bin/env bash
# Start PatchPilot (API + dashboard + feed watcher) on 127.0.0.1:8000.
#   LLM_MODE=cache scripts/run_agent.sh     # stage safety net: cached model answers only
#   PP_DEMO=1 scripts/run_agent.sh          # with the demo controls (scenario buttons, reset)
#   PP_HOST=0.0.0.0 scripts/run_agent.sh    # listen beyond this machine (set PP_API_TOKENS first)
# Every API call needs a token: PP_API_TOKENS=name:token,... or PP_API_TOKEN=token.
# Without one, a token is generated and printed at startup.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run uvicorn agent.main:app --host "${PP_HOST:-127.0.0.1}" --port "${PORT:-8000}"
