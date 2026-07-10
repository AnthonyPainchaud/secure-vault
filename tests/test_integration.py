"""End-to-end workflow tests spanning the whole stack: repository -> vault ->
fileformat -> aead/kdf -> storage, with the real file round-tripping through
disk between sessions.
"""

import os
import stat

import pytest

from securevault import Argon2Parameters
from securevault.errors import VaultAuthenticationError, VaultFormatError
from securevault.repository import VaultRepository
from securevault.storage import VAULT_FILE_MODE

FAST = Argon2Parameters(memory_kib=19_456, time_cost=1, parallelism=1)
PW = b"integration master password"


def test_full_lifecycle_create_add_close_reopen_retrieve(tmp_path):
    path = str(tmp_path / "vault.dat")

    # Session 1: create and populate, then close (persists to disk).
    with VaultRepository.create(path, PW, FAST) as repo:
        gh = repo.add_entry("github.com", "alice", "gh-secret", notes="work")
        aws = repo.add_entry("aws.amazon.com", "alice@example.com", "aws-secret")

    # Session 2: reopen from disk and retrieve exactly what was stored.
    with VaultRepository.open(path, PW) as repo:
        entries = {e.id: e for e in repo.list_entries()}
        assert set(entries) == {gh.id, aws.id}
        assert entries[gh.id].password == "gh-secret"
        assert entries[gh.id].notes == "work"
        assert entries[aws.id].username == "alice@example.com"
        assert entries[aws.id].password == "aws-secret"


def test_edits_persist_across_reopens(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        e = repo.add_entry("svc", "user", "v1")

    with VaultRepository.open(path, PW) as repo:
        repo.update_entry(e.id, password="v2")

    with VaultRepository.open(path, PW) as repo:
        assert repo.get_entry(e.id).password == "v2"
        repo.delete_entry(e.id)

    with VaultRepository.open(path, PW) as repo:
        assert repo.list_entries() == []


def test_wrong_master_password_on_reopen(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        repo.add_entry("svc", "user", "pw")

    with pytest.raises(VaultAuthenticationError):
        VaultRepository.open(path, b"not the password")


@pytest.mark.parametrize(
    "corrupt",
    [
        pytest.param(lambda d: d[:-1], id="truncated"),
        pytest.param(lambda d: d + b"\x00", id="trailing-garbage"),
        pytest.param(lambda d: b"XXXX" + d[4:], id="bad-magic"),
        pytest.param(lambda d: d[:20] + bytes([d[20] ^ 0x01]) + d[21:], id="flipped-salt-byte"),
        pytest.param(lambda d: d[:-1] + bytes([d[-1] ^ 0x01]), id="flipped-body-tag-byte"),
    ],
)
def test_corrupted_vault_file_is_rejected(tmp_path, corrupt):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        repo.add_entry("svc", "user", "pw")

    data = bytearray(open(path, "rb").read())
    with open(path, "wb") as handle:
        handle.write(corrupt(bytes(data)))

    # Structural damage -> VaultFormatError; authenticated-data damage ->
    # VaultAuthenticationError. Either way, the open fails loudly and never
    # returns partial data.
    with pytest.raises((VaultFormatError, VaultAuthenticationError)):
        VaultRepository.open(path, PW)


def test_vault_file_is_owner_only(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        repo.add_entry("svc", "user", "pw")

    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == VAULT_FILE_MODE  # 0o600, no group/other access


def test_no_plaintext_survives_on_disk_after_full_workflow(tmp_path):
    path = str(tmp_path / "vault.dat")
    secret_pw = "PLAINTEXT-CANARY-8b21f6"
    secret_note = "NOTE-CANARY-0af73c"
    with VaultRepository.create(path, PW, FAST) as repo:
        repo.add_entry("service.example", "user@example.com", secret_pw, notes=secret_note)

    on_disk = open(path, "rb").read()
    assert secret_pw.encode() not in on_disk
    assert secret_note.encode() not in on_disk
    assert b"service.example" not in on_disk  # metadata is encrypted too
    assert b"user@example.com" not in on_disk


def test_temp_files_do_not_linger_in_vault_directory(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        for i in range(5):
            repo.add_entry(f"svc{i}", "user", "pw")

    leftovers = [name for name in os.listdir(tmp_path) if name.startswith(".vault-")]
    assert leftovers == []
