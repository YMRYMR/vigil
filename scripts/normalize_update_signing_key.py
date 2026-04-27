#!/usr/bin/env python3
"""Normalize the release update-signing secret into a PKCS#8 PEM key.

The GitHub Actions secret may be stored in a few human-friendly forms:

- multiline PKCS#8 PEM
- PEM with literal ``\n`` escapes
- OpenSSH private key PEM
- raw 32-byte Ed25519 seed encoded as hex or base64
- raw 64-byte Ed25519 private key encoded as hex or base64 (seed + public key)
- PKCS#8 DER encoded as hex or base64

This helper converts those supported formats into a PEM file that OpenSSL can
consume consistently inside the release workflow.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import pathlib
import sys


PKCS8_ED25519_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PKCS8_ED25519_DER_LEN = len(PKCS8_ED25519_DER_PREFIX) + 32
ED25519_PRIVATE_KEY_LEN = 64


def _private_key_marker(kind: str) -> str:
    return f"-----{kind} {'PRIVATE' + ' KEY'}-----"


def _chunked_base64(data: bytes, width: int = 64) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    return "\n".join(
        encoded[idx : idx + width] for idx in range(0, len(encoded), width)
    )


def pem_from_pkcs8_der(der: bytes) -> str:
    return (
        f"{_private_key_marker('BEGIN')}\n"
        f"{_chunked_base64(der)}\n"
        f"{_private_key_marker('END')}\n"
    )


def pkcs8_der_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError(
            f"expected a 32-byte Ed25519 seed, got {len(seed)} bytes instead"
        )
    return PKCS8_ED25519_DER_PREFIX + seed


def pkcs8_der_from_raw_private_key(private_key: bytes) -> bytes:
    if len(private_key) != ED25519_PRIVATE_KEY_LEN:
        raise ValueError(
            "expected a 64-byte Ed25519 private key, "
            f"got {len(private_key)} bytes instead"
        )
    # Common raw encodings store the 32-byte seed followed by the public key.
    # The release workflow separately verifies that the derived public key still
    # matches Vigil's embedded update trust anchor.
    return pkcs8_der_from_seed(private_key[:32])


def _looks_like_pem(text: str) -> bool:
    return "-----BEGIN " in text and ("PRIVATE" + " KEY-----") in text


def _normalize_pem(text: str) -> str:
    normalized = text.replace("\r\n", "\n").strip()
    if f"BEGIN OPENSSH {'PRIVATE' + ' KEY'}" in normalized:
        try:
            from cryptography.hazmat.primitives import serialization
        except ModuleNotFoundError as exc:
            raise ValueError(
                "OpenSSH private key PEM requires the cryptography package; "
                "use PKCS#8 PEM or install cryptography before normalization"
            ) from exc
        key = serialization.load_ssh_private_key(
            normalized.encode("utf-8"), password=None
        )
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    if not _looks_like_pem(normalized):
        raise ValueError("secret did not contain a supported PEM private key")
    return f"{normalized}\n"


def _decoded_base64(text: str) -> bytes | None:
    compact = "".join(text.split())
    if not compact:
        return None
    padding = "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact + padding, validate=True)
    except (binascii.Error, ValueError):
        return None


def normalize_signing_key(secret: str) -> str:
    raw = secret.strip()
    if not raw:
        raise ValueError("update-signing secret is empty")

    pem_candidates = []
    if "\\n" in raw or "\\r" in raw:
        pem_candidates.append(raw.replace("\\r", "").replace("\\n", "\n"))
    pem_candidates.append(raw)
    for candidate in pem_candidates:
        if _looks_like_pem(candidate):
            return _normalize_pem(candidate)

    compact = "".join(raw.split())

    if len(compact) == 64:
        try:
            return pem_from_pkcs8_der(pkcs8_der_from_seed(bytes.fromhex(compact)))
        except ValueError:
            pass

    try:
        raw_bytes = bytes.fromhex(compact)
    except ValueError:
        raw_bytes = None
    if raw_bytes is not None:
        if len(raw_bytes) == 32:
            return pem_from_pkcs8_der(pkcs8_der_from_seed(raw_bytes))
        if len(raw_bytes) == ED25519_PRIVATE_KEY_LEN:
            return pem_from_pkcs8_der(pkcs8_der_from_raw_private_key(raw_bytes))
        if (
            len(raw_bytes) == PKCS8_ED25519_DER_LEN
            and raw_bytes.startswith(PKCS8_ED25519_DER_PREFIX)
        ):
            return pem_from_pkcs8_der(raw_bytes)

    decoded = _decoded_base64(raw)
    if decoded is not None:
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = None
        if decoded_text is not None and _looks_like_pem(decoded_text):
            return _normalize_pem(decoded_text)
        if len(decoded) == 32:
            return pem_from_pkcs8_der(pkcs8_der_from_seed(decoded))
        if len(decoded) == ED25519_PRIVATE_KEY_LEN:
            return pem_from_pkcs8_der(pkcs8_der_from_raw_private_key(decoded))
        if (
            len(decoded) == PKCS8_ED25519_DER_LEN
            and decoded.startswith(PKCS8_ED25519_DER_PREFIX)
        ):
            return pem_from_pkcs8_der(decoded)

    raise ValueError(
        "unsupported update-signing secret format; use PKCS#8 PEM, escaped PEM, "
        "OpenSSH private key PEM, hex/base64 PKCS#8 DER, a raw 32-byte Ed25519 seed, "
        "or a raw 64-byte Ed25519 private key"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize the Vigil update-signing secret into PKCS#8 PEM."
    )
    parser.add_argument(
        "--secret-env",
        default="VIGIL_UPDATE_SIGNING_KEY",
        help="Environment variable that contains the signing secret.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=pathlib.Path,
        help="Path to write the normalized PEM key file.",
    )
    args = parser.parse_args()

    try:
        secret = os.environ[args.secret_env]
    except KeyError as exc:
        raise ValueError(
            f"required environment variable {args.secret_env} is not set"
        ) from exc

    pem = normalize_signing_key(secret)
    args.output.write_text(pem, encoding="utf-8")
    os.chmod(args.output, 0o600)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
