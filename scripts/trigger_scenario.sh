#!/usr/bin/env bash
# Publish a scenario's advisory into the feed, as if it had just arrived.
#   scripts/trigger_scenario.sh log4shell | trojan | zeroday | badupdate
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f "scenarios/$1.json" ]] || { echo "unknown scenario: $1 (have: $(ls scenarios | sed 's/.json//' | xargs))"; exit 1; }
mkdir -p feed && cp "scenarios/$1.json" feed/
echo "advisory $1 published to feed/"
