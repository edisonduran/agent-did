"""The one Ed25519 verification rule of the SDK (RFC-001 §7), shared by every verification path.

Ed25519 implementations disagree on edge cases: ``@noble/curves`` follows ZIP-215 by default (it accepts
non-canonical encodings and checks the cofactored equation), libsodium (PyNaCl) is stricter and cofactorless.
A signature must not verify in one SDK and fail in the other, so both apply the same rule before the equation:

* the signature is 64 bytes and the public key 32 bytes;
* ``S`` is canonical (``S < L``);
* the public key ``A`` and the signature point ``R`` are canonical encodings of points of the prime-order
  subgroup: not of small order (this includes the identity) and without a torsion component.

With ``A`` and ``R`` in the prime-order subgroup the cofactored and cofactorless equations agree, so what is
accepted does not depend on which one a library implements. The point checks are made explicitly (libsodium's
own check of torsion in ``A`` is only probabilistic). TypeScript parity: ``sdk/src/crypto/ed25519-verify.ts``.
"""

from __future__ import annotations

import re

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


def _is_acceptable_point(encoded: bytes) -> bool:
    # canonical encoding, on the curve, in the prime-order subgroup and not of small order
    return bool(crypto_core_ed25519_is_valid_point(encoded))


def verify_ed25519(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature under the SDK rule above. Never raises; malformed input is ``False``."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    if not _is_acceptable_point(public_key) or not _is_acceptable_point(signature[:32]):
        return False
    try:
        VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError, TypeError):
        return False
    return True


_SIGNATURE_HEX = re.compile(r"[0-9a-fA-F]{128}")


def decode_signature_hex(signature: str) -> bytes:
    """Decode a payload signature written as hex: exactly 128 hex digits (64 bytes), nothing else (no spaces, no
    prefix). Raises ``ValueError`` otherwise, so both SDKs accept the same strings."""
    if not isinstance(signature, str) or _SIGNATURE_HEX.fullmatch(signature) is None:
        raise ValueError("A signature must be 128 hex digits")
    return bytes.fromhex(signature)
