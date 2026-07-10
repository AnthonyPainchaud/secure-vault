"""Authenticated encryption wrapper around AES-256-GCM.

The nonce is generated *inside* :func:`encrypt` from the OS CSPRNG and returned
alongside the ciphertext. Callers cannot supply a nonce, which makes the single
most dangerous GCM mistake -- reusing a (key, nonce) pair -- unrepresentable at
this API. See DESIGN.md for why fresh random 96-bit nonces are safe given the
whole-file-rewrite usage pattern.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import VaultAuthenticationError

#: AES-256 key length in bytes.
KEY_LENGTH = 32

#: GCM nonce length in bytes (96 bits, the standard/most-tested GCM nonce size).
NONCE_LENGTH = 12

#: GCM authentication tag length in bytes (128 bits).
TAG_LENGTH = 16


@dataclass(frozen=True)
class AeadCiphertext:
    """Output of :func:`encrypt`.

    ``blob`` is ``ciphertext || tag`` exactly as returned by the underlying
    library (the tag is appended, not a separate field), so it is stored and fed
    back verbatim.
    """

    nonce: bytes
    blob: bytes


def encrypt(key: bytes | bytearray, plaintext: bytes, associated_data: bytes) -> AeadCiphertext:
    """Encrypt ``plaintext`` under ``key`` with a fresh random nonce.

    ``associated_data`` is authenticated but not encrypted; tampering with it
    causes decryption to fail.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_LENGTH)
    blob = AESGCM(bytes(key)).encrypt(nonce, plaintext, associated_data)
    return AeadCiphertext(nonce=nonce, blob=blob)


def decrypt(
    key: bytes | bytearray,
    nonce: bytes,
    blob: bytes,
    associated_data: bytes,
) -> bytes:
    """Verify and decrypt ``blob`` (``ciphertext || tag``).

    Raises :class:`VaultAuthenticationError` on any authentication failure --
    wrong key, tampered ciphertext/tag/nonce, or tampered associated data -- and
    never returns partially decrypted data. A structurally wrong nonce or a blob
    too short to contain a tag is treated the same way (loud failure), rather
    than surfacing a different, information-bearing error.
    """
    if len(key) != KEY_LENGTH:
        raise ValueError(f"key must be {KEY_LENGTH} bytes, got {len(key)}")
    if len(nonce) != NONCE_LENGTH or len(blob) < TAG_LENGTH:
        raise VaultAuthenticationError()
    try:
        return AESGCM(bytes(key)).decrypt(nonce, blob, associated_data)
    except InvalidTag as exc:
        raise VaultAuthenticationError() from exc
