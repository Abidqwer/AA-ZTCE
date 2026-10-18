"""Signing-provider seam. Only the software Ed25519 provider is implemented.

This interface does not imply hardware custody, attestation, PQC negotiation,
key wrapping, or migration of the current Ed25519 wire protocol.
"""
from typing import Protocol
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyProvider(Protocol):
    algorithm: str
    key_id: str
    def sign(self, message: bytes) -> bytes: ...
    def public_key(self): ...


class SoftwareEd25519:
    algorithm = 'Ed25519'
    def __init__(self, key=None, key_id='gateway-software'):
        self.key_id = key_id
        self._key = key or Ed25519PrivateKey.generate()
    def sign(self, message): return self._key.sign(message)
    def public_key(self): return self._key.public_key()
