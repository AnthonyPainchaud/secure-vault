"""securevault -- cryptographic core for a local encrypted password vault.

This package provides key derivation, authenticated encryption, the on-disk
container format, and the envelope create/open/save flow. It does not implement a
CLI or an entry/record model; the vault body is treated as opaque bytes.
"""

from .errors import VaultAuthenticationError, VaultError, VaultFormatError
from .kdf import Argon2Parameters
from .vault import UnlockedVault, create, open_vault

__all__ = [
    "Argon2Parameters",
    "UnlockedVault",
    "VaultAuthenticationError",
    "VaultError",
    "VaultFormatError",
    "create",
    "open_vault",
]

__version__ = "0.1.0"
