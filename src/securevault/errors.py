"""Exception hierarchy for the vault.

The distinction between the two concrete errors is deliberate and security
relevant:

- ``VaultFormatError`` means the bytes are not a well-formed vault (bad magic,
  unsupported version, structurally impossible lengths, out-of-range KDF
  parameters). It depends only on the file, never on the password, so raising it
  leaks nothing about the secret.

- ``VaultAuthenticationError`` means a well-formed vault failed authentication.
  This covers *both* an incorrect password and a tampered/corrupted vault, and
  the two are intentionally indistinguishable: same type, same message. A caller
  must not be able to tell "wrong password" from "someone modified the file",
  and neither reveals whether a guess was close.
"""


class VaultError(Exception):
    """Base class for all vault errors."""


class VaultFormatError(VaultError):
    """The data is not a structurally valid vault file."""


class VaultAuthenticationError(VaultError):
    """Authentication failed: wrong password, or the vault was tampered with.

    The message is intentionally generic and identical for both causes.
    """

    _MESSAGE = "vault authentication failed: wrong password, or the vault is corrupt or tampered"

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self._MESSAGE)
