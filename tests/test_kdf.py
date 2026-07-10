import pytest

from securevault.errors import VaultFormatError
from securevault.kdf import (
    KEY_LENGTH,
    MAX_MEMORY_KIB,
    MAX_PARALLELISM,
    MAX_TIME_COST,
    MIN_MEMORY_KIB,
    Argon2Parameters,
    SALT_LENGTH,
    derive_key,
)

SALT = b"\x02" * SALT_LENGTH
# Minimum in-range parameters keep the tests fast while still exercising Argon2id.
FAST = Argon2Parameters(memory_kib=MIN_MEMORY_KIB, time_cost=1, parallelism=1)


def test_derive_key_has_expected_length():
    assert len(derive_key(b"pw", SALT, FAST)) == KEY_LENGTH


def test_custom_output_length():
    assert len(derive_key(b"pw", SALT, FAST, length=64)) == 64


def test_derivation_is_deterministic():
    assert derive_key(b"pw", SALT, FAST) == derive_key(b"pw", SALT, FAST)


def test_different_password_yields_different_key():
    assert derive_key(b"one", SALT, FAST) != derive_key(b"two", SALT, FAST)


def test_different_salt_yields_different_key():
    other_salt = b"\x03" * SALT_LENGTH
    assert derive_key(b"pw", SALT, FAST) != derive_key(b"pw", other_salt, FAST)


def test_different_params_yield_different_key():
    slower = Argon2Parameters(memory_kib=MIN_MEMORY_KIB, time_cost=2, parallelism=1)
    assert derive_key(b"pw", SALT, FAST) != derive_key(b"pw", SALT, slower)


def test_default_parameters_match_rfc_recommendation():
    params = Argon2Parameters()
    assert (params.memory_kib, params.time_cost, params.parallelism) == (65_536, 3, 4)


@pytest.mark.parametrize(
    "params",
    [
        Argon2Parameters(memory_kib=MIN_MEMORY_KIB - 1),
        Argon2Parameters(memory_kib=MAX_MEMORY_KIB + 1),
        Argon2Parameters(time_cost=0),
        Argon2Parameters(time_cost=MAX_TIME_COST + 1),
        Argon2Parameters(parallelism=0),
        Argon2Parameters(parallelism=MAX_PARALLELISM + 1),
    ],
)
def test_out_of_range_parameters_are_rejected(params):
    with pytest.raises(VaultFormatError):
        params.validate()


def test_derive_key_rejects_wrong_salt_length():
    with pytest.raises(VaultFormatError):
        derive_key(b"pw", b"too-short", FAST)
