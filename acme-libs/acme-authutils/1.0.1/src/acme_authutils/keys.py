"""Load signing keys by id from the key directory."""
import hashlib
import os
import re

KEY_DIR = os.environ.get("ACME_KEY_DIR", "/app/keys")

_KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def load_key(key_id):
    """Return the key material stored under `key_id`.

    Key ids are plain names; anything that could leave KEY_DIR is rejected.
    """
    if not _KEY_ID.fullmatch(key_id or ""):
        raise ValueError("invalid key id")
    path = os.path.join(KEY_DIR, key_id)
    with open(path, "rb") as fh:
        return fh.read()


def fingerprint(key):
    """Short, printable fingerprint of a key."""
    return hashlib.sha256(key).hexdigest()[:16]
