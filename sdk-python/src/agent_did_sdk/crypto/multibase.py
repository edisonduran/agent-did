"""Multibase / Multicodec encoding and decoding for Ed25519 public keys.

Implements W3C-compliant publicKeyMultibase encoding:
  - 'z' prefix for Base58btc (Multibase)
  - 0xed01 prefix for Ed25519 public keys (Multicodec)

Also supports decoding legacy 'z' + hex format from SDK v0.1.0 for
backward compatibility.
"""

from __future__ import annotations

import re

# Multicodec prefix for Ed25519 public keys (varint-encoded 0xed)
_ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])

# Base58btc alphabet (Bitcoin variant)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode *data* using Base58btc (Bitcoin alphabet)."""
    n = int.from_bytes(data, "big")
    result: list[str] = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_B58_ALPHABET[remainder : remainder + 1].decode())
    # Preserve leading zero bytes
    for byte in data:
        if byte == 0:
            result.append("1")
        else:
            break
    return "".join(reversed(result))


def _base58_decode(s: str) -> bytes:
    """Decode a Base58btc-encoded string back to bytes."""
    n = 0
    for char in s:
        idx = _B58_ALPHABET.find(char.encode())
        if idx < 0:
            raise ValueError(f"Invalid Base58btc character: {char!r}")
        n = n * 58 + idx
    # Count leading '1' characters (represent 0x00 bytes)
    leading_zeros = 0
    for char in s:
        if char == "1":
            leading_zeros += 1
        else:
            break
    # Convert integer to bytes
    if n == 0:
        result = b""
    else:
        byte_length = (n.bit_length() + 7) // 8
        result = n.to_bytes(byte_length, "big")
    return b"\x00" * leading_zeros + result


def encode_public_key_multibase(raw_public_key: bytes) -> str:
    """Encode a raw Ed25519 public key into W3C-compliant publicKeyMultibase.

    Format: ``z`` + Base58btc(``0xed01`` + *raw_public_key*)

    Args:
        raw_public_key: 32-byte Ed25519 public key.

    Returns:
        Multibase-encoded string (e.g. ``z6Mkf5rGMoatrSj1f...``).
    """
    if len(raw_public_key) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw_public_key)}")
    prefixed = _ED25519_MULTICODEC_PREFIX + raw_public_key
    return f"z{_base58_encode(prefixed)}"


def decode_public_key_multibase(encoded: str) -> bytes:
    """Decode a publicKeyMultibase string back to a raw Ed25519 public key.

    Accepts both:
      - Standard format: ``z`` + Base58btc(``0xed01`` + raw_key) (W3C compliant)
      - Legacy format: ``z`` + hex(raw_key) (SDK v0.1.0 simplified)

    Args:
        encoded: The publicKeyMultibase string.

    Returns:
        32-byte raw Ed25519 public key.
    """
    if not encoded.startswith("z"):
        raise ValueError(f"Unsupported multibase prefix: {encoded[0]!r}. Only 'z' (Base58btc) is supported.")

    value = encoded[1:]

    # Attempt standard Base58btc decode with multicodec prefix
    try:
        decoded = _base58_decode(value)
        if (
            len(decoded) == 34
            and decoded[0] == _ED25519_MULTICODEC_PREFIX[0]
            and decoded[1] == _ED25519_MULTICODEC_PREFIX[1]
        ):
            return decoded[2:]
        # Base58btc decoded but no multicodec prefix — could be raw 32-byte key
        if len(decoded) == 32:
            return decoded
    except ValueError:
        pass  # Not valid Base58btc — fall through to legacy hex

    # Legacy fallback: 'z' + hex (SDK v0.1.0 format)
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return bytes.fromhex(value)

    raise ValueError("Unable to decode publicKeyMultibase: unrecognized format")
