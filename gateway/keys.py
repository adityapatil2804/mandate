"""Ed25519 key loading. Keys are generated on first run and stored outside the agent's reach."""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def load_or_create(path: str | os.PathLike) -> Ed25519PrivateKey:
    p = Path(path)
    if p.exists():
        return serialization.load_pem_private_key(p.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(p, 0o600)
    return key
