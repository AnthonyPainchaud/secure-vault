"""Cryptographically secure password generation.

Every random choice -- including which characters to pick and how to shuffle
them -- goes through the `secrets` module or `secrets.SystemRandom`, never the
`random` module. `secrets.SystemRandom` is `random.Random` seeded from
`os.urandom`; the stdlib documents it as suitable for security-sensitive work,
unlike the module-level `random` functions (Mersenne Twister, not a CSPRNG).
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"
# Characters that are easily confused when handwritten or read aloud.
AMBIGUOUS = set("Il1O0")

MIN_LENGTH = 8
MAX_LENGTH = 256
DEFAULT_LENGTH = 20


@dataclass(frozen=True)
class PasswordPolicy:
    length: int = DEFAULT_LENGTH
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False

    def pools(self) -> list[str]:
        """The character pools implied by this policy, one entry per enabled
        category, ambiguous characters stripped if requested. Raises
        ValueError if no characters remain to draw from."""
        selected = []
        if self.use_upper:
            selected.append(UPPER)
        if self.use_lower:
            selected.append(LOWER)
        if self.use_digits:
            selected.append(DIGITS)
        if self.use_symbols:
            selected.append(SYMBOLS)
        if not selected:
            raise ValueError("at least one character category must be enabled")

        if self.exclude_ambiguous:
            selected = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in selected]
            selected = [pool for pool in selected if pool]
        if not selected:
            raise ValueError(
                "excluding ambiguous characters removed every selected character category"
            )
        return selected

    def validate(self) -> None:
        if not (MIN_LENGTH <= self.length <= MAX_LENGTH):
            raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
        pools = self.pools()
        if self.length < len(pools):
            raise ValueError(
                f"length {self.length} is too short to include at least one "
                f"character from each of the {len(pools)} selected categories"
            )


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Generate a password satisfying ``policy``.

    Guarantees at least one character from every selected category (by drawing
    one from each pool first), fills the remaining length from the combined
    pool, then shuffles with a CSPRNG so the guaranteed-category characters
    aren't predictably placed at the front.
    """
    policy = policy or PasswordPolicy()
    policy.validate()
    pools = policy.pools()
    combined = "".join(pools)

    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(combined) for _ in range(policy.length - len(chars))]

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def estimate_entropy_bits(password: str) -> float:
    """A crude, honest lower-bound entropy estimate: log2(pool_size) * length.

    This assumes uniform random selection from the *apparent* character pool,
    which overestimates the true entropy of a human-chosen (non-random)
    password such as a dictionary word or a name. It exists only to flag
    obviously weak master passwords, never to certify a password as strong --
    see THREAT_MODEL.md N9.
    """
    if not password:
        return 0.0
    pool = 0
    if any(c in UPPER for c in password):
        pool += len(UPPER)
    if any(c in LOWER for c in password):
        pool += len(LOWER)
    if any(c in DIGITS for c in password):
        pool += len(DIGITS)
    if any(c not in UPPER and c not in LOWER and c not in DIGITS for c in password):
        pool += len(SYMBOLS)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)
