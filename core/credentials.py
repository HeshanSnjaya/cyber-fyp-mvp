"""Project-local AWS credential storage.

Design goals (per project requirements):

* Keys are **entered in the app** and **saved inside the project**, never read
  from ``~/.aws`` or environment variables.
* At rest the keys are **encrypted** (Fernet / AES-128-CBC + HMAC) using a key
  file generated on first use. Both the encrypted blob and the key live under
  ``.secrets/`` which is git-ignored, so nothing sensitive is committed.
* When live AWS mode is used, the caller passes these saved keys *explicitly*
  to boto3, guaranteeing the ambient credential chain is bypassed.

If the optional ``cryptography`` package is unavailable we fall back to a
clearly-labelled obfuscated store so the app still runs, but real encryption is
the default and is listed in requirements.txt.
"""

from __future__ import annotations

import base64
import json
import os

_SECRETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".secrets")
_KEY_FILE = os.path.join(_SECRETS_DIR, "fernet.key")
_CRED_FILE = os.path.join(_SECRETS_DIR, "aws_credentials.enc")

try:  # Prefer real encryption.
    from cryptography.fernet import Fernet

    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - fallback path
    _HAS_CRYPTO = False


def _ensure_dir():
    os.makedirs(_SECRETS_DIR, exist_ok=True)


def _get_fernet():
    """Load or lazily create the Fernet key used to encrypt credentials."""
    _ensure_dir()
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as fh:
            key = fh.read()
    else:
        key = Fernet.generate_key()
        with open(_KEY_FILE, "wb") as fh:
            fh.write(key)
    return Fernet(key)


def _encrypt(data: bytes) -> bytes:
    if _HAS_CRYPTO:
        return _get_fernet().encrypt(data)
    # Fallback: base64 obfuscation (NOT secure — install `cryptography`).
    return b"PLAIN:" + base64.b64encode(data)


def _decrypt(blob: bytes) -> bytes:
    if blob.startswith(b"PLAIN:"):
        return base64.b64decode(blob[len(b"PLAIN:"):])
    return _get_fernet().decrypt(blob)


def save_credentials(
    access_key_id: str,
    secret_access_key: str,
    region: str = "us-east-1",
    session_token: str = "",
) -> None:
    """Encrypt and persist AWS credentials inside the project."""
    _ensure_dir()
    payload = {
        "aws_access_key_id": access_key_id.strip(),
        "aws_secret_access_key": secret_access_key.strip(),
        "region": (region or "us-east-1").strip(),
        "aws_session_token": (session_token or "").strip(),
    }
    blob = _encrypt(json.dumps(payload).encode("utf-8"))
    with open(_CRED_FILE, "wb") as fh:
        fh.write(blob)


def load_credentials():
    """Return the saved credential dict, or ``None`` if none are stored."""
    if not os.path.exists(_CRED_FILE):
        return None
    try:
        with open(_CRED_FILE, "rb") as fh:
            blob = fh.read()
        return json.loads(_decrypt(blob).decode("utf-8"))
    except Exception:
        return None


def has_saved_credentials() -> bool:
    return load_credentials() is not None


def clear_credentials() -> None:
    """Delete any stored credentials (keeps the encryption key file)."""
    if os.path.exists(_CRED_FILE):
        os.remove(_CRED_FILE)


def is_encryption_available() -> bool:
    return _HAS_CRYPTO


def masked_access_key():
    """Return a masked form of the stored access key for safe display."""
    creds = load_credentials()
    if not creds:
        return None
    key = creds.get("aws_access_key_id", "")
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]
