import pytest

from securevault import Argon2Parameters
from securevault.errors import VaultLockedError
from securevault.repository import VaultRepository

FAST = Argon2Parameters(memory_kib=19_456, time_cost=1, parallelism=1)
PW = b"locking test password"


def test_second_open_while_first_is_held_is_refused(tmp_path):
    path = str(tmp_path / "vault.dat")
    first = VaultRepository.create(path, PW, FAST)
    try:
        with pytest.raises(VaultLockedError):
            VaultRepository.open(path, PW)
    finally:
        first.close()


def test_lock_is_released_on_close(tmp_path):
    path = str(tmp_path / "vault.dat")
    VaultRepository.create(path, PW, FAST).close()
    # A fresh open must succeed now that the first session released the lock.
    second = VaultRepository.open(path, PW)
    second.close()


def test_failed_open_releases_lock(tmp_path):
    path = str(tmp_path / "vault.dat")
    VaultRepository.create(path, PW, FAST).close()
    with pytest.raises(Exception):
        VaultRepository.open(path, b"wrong password")
    # The lock taken during the failed open must have been released, so a
    # correct open still works.
    good = VaultRepository.open(path, PW)
    good.close()
