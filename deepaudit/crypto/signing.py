#!/usr/bin/env python3
from __future__ import annotations
"""Bundle signing: Ed25519 with RFC 8785-style canonicalization."""

import hashlib
import json
from pathlib import Path
from typing import Any


def canonicalize(data: dict[str, Any]) -> bytes:
    """Return deterministic canonical bytes for a JSON-serializable dict.

    Prefer RFC 8785 (JCS) when the ``jcs`` package is installed; otherwise fall
    back to a stable, sorted, compact JSON representation.
    """
    try:
        import jcs  # type: ignore[import-not-found]

        return jcs.canonicalize(data)
    except Exception:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


def _load_or_generate_key(key_path: Path | None) -> Any:
    """Load an Ed25519 private key from PEM, or generate and persist one."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    if key_path is None:
        return Ed25519PrivateKey.generate()

    key_path = Path(key_path)
    if key_path.exists():
        pem = key_path.read_bytes()
        return serialization.load_pem_private_key(pem, password=None)

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def sign_bundle(
    bundle_data: dict[str, Any],
    key_path: Path | None = None,
) -> dict[str, Any]:
    """Sign a canonicalized bundle payload and return a signature object."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception as exc:
        raise RuntimeError(
            "Ed25519 signing requires the 'cryptography' package. "
            "Install it or run with the 'crypto' extra."
        ) from exc

    payload = canonicalize(bundle_data)
    digest = hashlib.sha256(payload).hexdigest()
    key = _load_or_generate_key(key_path)
    signature = key.sign(payload).hex()
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    return {
        "algorithm": "ed25519",
        "canonicalization": "RFC 8785",
        "public_key": public_key,
        "signature": signature,
        "signed_payload_sha256": digest,
        "fingerprint": digest[:32],
    }


def verify_signature(
    bundle_data: dict[str, Any],
    signature: dict[str, Any],
) -> bool:
    """Verify the Ed25519 signature over a canonicalized bundle payload."""
    if signature.get("algorithm") != "ed25519":
        return False
    if not all(
        k in signature for k in ("public_key", "signature", "signed_payload_sha256")
    ):
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except Exception:
        return False

    payload = canonicalize(bundle_data)
    if hashlib.sha256(payload).hexdigest() != signature["signed_payload_sha256"]:
        return False

    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(signature["public_key"])
        )
        public_key.verify(bytes.fromhex(signature["signature"]), payload)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
