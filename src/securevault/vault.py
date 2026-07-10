"""Envelope encryption: the top-level create / open / save / change-password flow.

A random 256-bit data-encryption key (DEK) encrypts the vault body. The DEK is
itself encrypted (wrapped) under a key-encryption key (KEK) derived from the
master password with Argon2id. This buys two things: Argon2 runs only once per
unlock (saves are cheap), and changing the master password only re-wraps the DEK
instead of re-deriving over the whole vault.

Secrets are confined to as few and as short-lived references as the language
allows and the mutable ones are wiped on close, but see memory.py / THREAT_MODEL
for why erasure is best-effort only.
"""

from __future__ import annotations

import os

from . import aead, fileformat
from .kdf import KEY_LENGTH, SALT_LENGTH, Argon2Parameters, derive_key
from .memory import wipe

DEK_LENGTH = fileformat.DEK_LENGTH


def create(
    password: bytes,
    plaintext: bytes,
    params: Argon2Parameters | None = None,
) -> bytes:
    """Create a brand-new vault file from ``plaintext``.

    Generates a fresh salt and a fresh random DEK, wraps the DEK under the
    password-derived KEK, encrypts the body under the DEK, and returns the
    serialized file bytes. The same code path is used regardless of whether the
    plaintext is empty, so a new/empty vault is never a weaker special case.
    """
    params = params or Argon2Parameters()
    params.validate()

    salt = os.urandom(SALT_LENGTH)
    dek = bytearray(os.urandom(DEK_LENGTH))
    kek = derive_key(password, salt, params)
    try:
        kdf_header = fileformat.build_kdf_header(params, salt)
        wrapped = aead.encrypt(kek, bytes(dek), associated_data=kdf_header)

        counter = 0
        full_header = fileformat.build_full_header(params, salt, counter)
        body = aead.encrypt(dek, plaintext, associated_data=full_header)

        return fileformat.serialize(
            kdf_header=kdf_header,
            counter=counter,
            dek_nonce=wrapped.nonce,
            dek_blob=wrapped.blob,
            body_nonce=body.nonce,
            body_blob=body.blob,
        )
    finally:
        wipe(dek)
        del kek  # immutable bytes: cannot be wiped, only dereferenced


def open_vault(password: bytes, data: bytes) -> "UnlockedVault":
    """Parse, verify and decrypt a vault file, returning an unlocked session.

    Order of operations matters for the no-information-leak guarantee: the file
    is structurally validated first (password-independent), then the KEK is
    derived (always paying the full Argon2 cost), then the DEK is unwrapped. An
    incorrect password fails at the unwrap step with exactly the same error as a
    tampered vault, so the two cannot be distinguished.
    """
    parsed = fileformat.parse(data)  # VaultFormatError on structural problems

    kek = derive_key(password, parsed.salt, parsed.params)
    try:
        dek_bytes = aead.decrypt(
            kek, parsed.dek_nonce, parsed.dek_blob, associated_data=parsed.kdf_header
        )
    finally:
        del kek
    dek = bytearray(dek_bytes)
    del dek_bytes  # drop the immutable copy we cannot wipe

    body = aead.decrypt(
        dek, parsed.body_nonce, parsed.body_blob, associated_data=parsed.full_header
    )

    return UnlockedVault(
        params=parsed.params,
        salt=parsed.salt,
        counter=parsed.counter,
        kdf_header=parsed.kdf_header,
        dek_nonce=parsed.dek_nonce,
        dek_blob=parsed.dek_blob,
        dek=dek,
        plaintext=bytearray(body),
    )


class UnlockedVault:
    """An open vault holding the DEK and decrypted plaintext in memory.

    Use as a context manager so the mutable secret buffers are wiped on exit::

        with open_vault(password, data) as vault:
            ...
            new_data = vault.save(new_plaintext)
    """

    def __init__(
        self,
        *,
        params: Argon2Parameters,
        salt: bytes,
        counter: int,
        kdf_header: bytes,
        dek_nonce: bytes,
        dek_blob: bytes,
        dek: bytearray,
        plaintext: bytearray,
    ) -> None:
        self._params = params
        self._salt = salt
        self._counter = counter
        self._kdf_header = kdf_header
        self._dek_nonce = dek_nonce
        self._dek_blob = dek_blob
        self._dek = dek
        self._plaintext = plaintext
        self._closed = False

    # -- read-only views -------------------------------------------------

    @property
    def save_counter(self) -> int:
        return self._counter

    @property
    def parameters(self) -> Argon2Parameters:
        return self._params

    def read(self) -> bytes:
        """Return a copy of the current plaintext."""
        self._check_open()
        return bytes(self._plaintext)

    # -- mutating operations --------------------------------------------

    def save(self, new_plaintext: bytes) -> bytes:
        """Re-encrypt ``new_plaintext`` under the existing DEK and return the file.

        A fresh body nonce is used and the save counter is incremented. The
        wrapped-DEK block is reused unchanged: the DEK, KEK and its nonce are all
        unchanged, so re-emitting the identical wrap ciphertext leaks nothing.
        """
        self._check_open()
        new_counter = self._counter + 1
        full_header = fileformat.build_full_header(self._params, self._salt, new_counter)
        body = aead.encrypt(self._dek, new_plaintext, associated_data=full_header)

        data = fileformat.serialize(
            kdf_header=self._kdf_header,
            counter=new_counter,
            dek_nonce=self._dek_nonce,
            dek_blob=self._dek_blob,
            body_nonce=body.nonce,
            body_blob=body.blob,
        )

        wipe(self._plaintext)
        self._plaintext = bytearray(new_plaintext)
        self._counter = new_counter
        return data

    def change_password(
        self,
        new_password: bytes,
        new_params: Argon2Parameters | None = None,
    ) -> bytes:
        """Re-wrap the DEK under a new password (and optionally new KDF params).

        The DEK is preserved, so the body's confidentiality is unbroken; a fresh
        salt and KEK are derived and the wrapped DEK is regenerated. The body is
        re-encrypted too because its associated data (the full header) includes
        the changed salt. The save counter keeps increasing monotonically across
        password changes, since body nonces remain under the same DEK.
        """
        self._check_open()
        params = new_params or self._params
        params.validate()

        new_salt = os.urandom(SALT_LENGTH)
        kek = derive_key(new_password, new_salt, params)
        try:
            new_kdf_header = fileformat.build_kdf_header(params, new_salt)
            wrapped = aead.encrypt(kek, bytes(self._dek), associated_data=new_kdf_header)
        finally:
            del kek

        new_counter = self._counter + 1
        full_header = fileformat.build_full_header(params, new_salt, new_counter)
        body = aead.encrypt(self._dek, bytes(self._plaintext), associated_data=full_header)

        data = fileformat.serialize(
            kdf_header=new_kdf_header,
            counter=new_counter,
            dek_nonce=wrapped.nonce,
            dek_blob=wrapped.blob,
            body_nonce=body.nonce,
            body_blob=body.blob,
        )

        self._params = params
        self._salt = new_salt
        self._kdf_header = new_kdf_header
        self._dek_nonce = wrapped.nonce
        self._dek_blob = wrapped.blob
        self._counter = new_counter
        return data

    # -- lifecycle -------------------------------------------------------

    def close(self) -> None:
        """Wipe the mutable secret buffers (best-effort) and mark closed."""
        if self._closed:
            return
        wipe(self._dek)
        wipe(self._plaintext)
        self._closed = True

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("vault is closed")

    def __enter__(self) -> "UnlockedVault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
