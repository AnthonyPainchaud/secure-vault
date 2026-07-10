"""Key derivation from the master password using Argon2id.

The raw-key low-level API is used deliberately. ``argon2-cffi``'s high-level
``PasswordHasher`` produces a PHC verifier string for *checking* passwords; here
we need the derived bytes themselves as a key-encryption key, which is what
``hash_secret_raw`` returns.
"""

from __future__ import annotations

from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from .errors import VaultFormatError

#: Length of the derived key-encryption key, in bytes (256 bits).
KEY_LENGTH = 32

#: Length of the per-vault salt, in bytes (128 bits).
SALT_LENGTH = 16

# Hard bounds on parameters read from a vault header. Because the header is
# plaintext and must be parsed *before* the key that authenticates it can be
# derived, an attacker can edit these values. Lowering them does not help an
# attacker (they still lack the password); raising ``memory_kib`` to an absurd
# value is a denial-of-service via allocation, so the upper bound is the
# load-bearing check. We enforce both directions for clarity.
MIN_MEMORY_KIB = 19_456        # OWASP floor (~19 MiB)
MAX_MEMORY_KIB = 1_048_576     # 1 GiB
MIN_TIME_COST = 1
MAX_TIME_COST = 16
MIN_PARALLELISM = 1
MAX_PARALLELISM = 8


@dataclass(frozen=True)
class Argon2Parameters:
    """Argon2id cost parameters.

    Defaults follow RFC 9106's second (memory-constrained) recommendation, which
    is appropriate for an interactive desktop unlock: 64 MiB of memory, three
    passes, four lanes.
    """

    memory_kib: int = 65_536   # 64 MiB
    time_cost: int = 3
    parallelism: int = 4

    def validate(self) -> None:
        """Raise ``VaultFormatError`` if any parameter is out of the safe range.

        Called before any Argon2 invocation so a hostile header cannot trigger a
        huge allocation.
        """
        if not MIN_MEMORY_KIB <= self.memory_kib <= MAX_MEMORY_KIB:
            raise VaultFormatError(
                f"argon2 memory_kib {self.memory_kib} outside "
                f"[{MIN_MEMORY_KIB}, {MAX_MEMORY_KIB}]"
            )
        if not MIN_TIME_COST <= self.time_cost <= MAX_TIME_COST:
            raise VaultFormatError(
                f"argon2 time_cost {self.time_cost} outside "
                f"[{MIN_TIME_COST}, {MAX_TIME_COST}]"
            )
        if not MIN_PARALLELISM <= self.parallelism <= MAX_PARALLELISM:
            raise VaultFormatError(
                f"argon2 parallelism {self.parallelism} outside "
                f"[{MIN_PARALLELISM}, {MAX_PARALLELISM}]"
            )


def derive_key(
    password: bytes,
    salt: bytes,
    params: Argon2Parameters,
    length: int = KEY_LENGTH,
) -> bytes:
    """Derive a key of ``length`` bytes from ``password`` and ``salt``.

    ``params`` is validated first, so this never runs Argon2 with out-of-range
    costs. The returned key is an immutable ``bytes`` object (an unavoidable
    consequence of the library API); callers that need to wipe it must copy it
    into a ``bytearray`` and accept that the original cannot be erased.
    """
    params.validate()
    if len(salt) != SALT_LENGTH:
        raise VaultFormatError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=length,
        type=Type.ID,
    )
