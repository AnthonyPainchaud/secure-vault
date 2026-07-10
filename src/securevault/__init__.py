"""securevault -- a local, offline, encrypted password vault.

The cryptographic core (key derivation, authenticated encryption, the on-disk
container format, and the envelope create/open/save flow) treats the vault body
as opaque bytes and is exported from here unchanged. The entry model
(`securevault.entries`), CRUD layer (`securevault.repository`), password
generator (`securevault.passwordgen`), and CLI (`securevault.cli`) are built on
top of it and imported separately -- the crypto core has no knowledge of them.
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
