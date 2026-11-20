"""Load signing keys by id from the key directory."""
import hashlib
import os

KEY_DIR = os.environ.get("ACME_KEY_DIR", "/app/keys")


def load_key(key_id):
    """Return the key material stored under `key_id`."""
    path = os.path.join(KEY_DIR, key_id)
    with open(path, "rb") as fh:
        return fh.read()


def fingerprint(key):
    """Short, printable fingerprint of a key."""
    return hashlib.sha256(key).hexdigest()[:16]
