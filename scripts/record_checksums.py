#!/usr/bin/env python3
"""Record the SHA-256 of every artifact in artifacts/ into artifacts/checksums.json.

Existing entries are never overwritten: the first recorded checksum is the one
the vetter trusts, so an artifact swapped afterwards shows up as a mismatch.
"""
import hashlib
import json
import pathlib

root = pathlib.Path(__file__).resolve().parent.parent / "artifacts"
path = root / "checksums.json"
sums = json.loads(path.read_text()) if path.exists() else {}

for pattern in ("maven/*/*/*.jar", "pypi/*/*/*.whl", "pypi/*/*/*.tar.gz"):
    for artifact in sorted(root.glob(pattern)):
        key = str(artifact.relative_to(root))
        if key not in sums:
            sums[key] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            print(f"  recorded {key}")

path.write_text(json.dumps(sums, indent=2, sort_keys=True) + "\n")
