#!/usr/bin/env bash
# Hour 0: fill artifacts/maven/ (the local "upstream repository") from Maven Central.
# Every jar is checked against Central's SHA-1 and its SHA-256 is recorded in
# artifacts/checksums.json, which the vetter later trusts.
set -euo pipefail
cd "$(dirname "$0")/.."

CENTRAL="${MAVEN_CENTRAL:-https://repo1.maven.org/maven2}"

# group:artifact:version
COORDS=(
  org.apache.logging.log4j:log4j-api:2.14.1
  org.apache.logging.log4j:log4j-core:2.14.1
  org.apache.logging.log4j:log4j-api:2.17.1
  org.apache.logging.log4j:log4j-core:2.17.1
)

fetch() {
  local url="$1" out="$2"
  if [[ -s "$out" ]]; then return 0; fi
  echo "  get $url"
  curl -fsSL "$url" -o "$out.tmp"
  local want got
  want="$(curl -fsSL "$url.sha1" | awk '{print $1}')"
  got="$(shasum -a 1 "$out.tmp" | awk '{print $1}')"
  if [[ "$want" != "$got" ]]; then
    echo "SHA-1 mismatch for $url (want $want, got $got)" >&2
    rm -f "$out.tmp"; exit 1
  fi
  mv "$out.tmp" "$out"
}

for c in "${COORDS[@]}"; do
  IFS=: read -r g a v <<<"$c"
  dir="artifacts/maven/$a/$v"
  mkdir -p "$dir"
  base="$CENTRAL/${g//.//}/$a/$v/$a-$v"
  fetch "$base.jar" "$dir/$a-$v.jar"
  fetch "$base-sources.jar" "$dir/$a-$v-sources.jar"
done

python3 scripts/record_checksums.py
echo "artifacts/ ready"
