"""AgentSigner protocol and LocalKeySigner implementation."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from nacl.signing import SigningKey


@runtime_checkable
class AgentSigner(Protocol):
    """Interface for signing operations.

    Implement this to integrate with external key management
    (KMS, HSM, hardware wallets) in production.
    """

    async def sign(self, payload: bytes) -> str:
        """Sign *payload* and return the signature as a hex string."""
        ...

    async def get_public_key(self) -> bytes:
        """Return the raw Ed25519 public key (32 bytes)."""
        ...


class LocalKeySigner:
    """Default signer using a local Ed25519 private key.

    Suitable for development, testing, and demo scenarios.
    """

    def __init__(self, private_key_hex: str) -> None:
        self._signing_key = SigningKey(bytes.fromhex(private_key_hex))

    async def sign(self, payload: bytes) -> str:
        signed = self._signing_key.sign(payload)
        return signed.signature.hex()

    async def get_public_key(self) -> bytes:
        return bytes(self._signing_key.verify_key)

    @staticmethod
    def generate() -> tuple["LocalKeySigner", str]:
        """Generate a new signer with a random key. Returns (signer, private_key_hex)."""
        sk = SigningKey.generate()
        hex_key = sk.encode().hex()
        return LocalKeySigner(hex_key), hex_key
