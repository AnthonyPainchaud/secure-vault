import pytest

from securevault import Argon2Parameters, VaultAuthenticationError
from securevault.repository import EntryNotFoundError, VaultRepository

FAST = Argon2Parameters(memory_kib=19_456, time_cost=1, parallelism=1)
PW = b"repository test password"


def test_create_refuses_to_overwrite_existing_file(tmp_path):
    path = tmp_path / "vault.dat"
    VaultRepository.create(str(path), PW, FAST).close()
    with pytest.raises(FileExistsError):
        VaultRepository.create(str(path), PW, FAST)


def test_new_vault_has_no_entries(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        assert repo.list_entries() == []


def test_add_get_list(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("github.com", "alice", "s3cr3t", notes="work account")
        assert repo.get_entry(entry.id) == entry
        assert repo.list_entries() == [entry]


def test_add_persists_across_reopen(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("github.com", "alice", "s3cr3t")

    with VaultRepository.open(path, PW) as repo:
        reopened = repo.get_entry(entry.id)
        assert reopened.service == "github.com"
        assert reopened.username == "alice"
        assert reopened.password == "s3cr3t"


def test_update_changes_only_given_fields(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("github.com", "alice", "old-pw", notes="original")
        updated = repo.update_entry(entry.id, password="new-pw")
        assert updated.password == "new-pw"
        assert updated.service == "github.com"
        assert updated.username == "alice"
        assert updated.notes == "original"
        assert updated.updated_at >= entry.updated_at


def test_update_persists(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("service", "user", "pw")
        repo.update_entry(entry.id, username="new-user")

    with VaultRepository.open(path, PW) as repo:
        assert repo.get_entry(entry.id).username == "new-user"


def test_delete_removes_entry_and_persists(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("service", "user", "pw")
        repo.delete_entry(entry.id)
        assert repo.list_entries() == []

    with VaultRepository.open(path, PW) as repo:
        assert repo.list_entries() == []


def test_operations_on_missing_entry_raise(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        with pytest.raises(EntryNotFoundError):
            repo.get_entry("doesnotexist")
        with pytest.raises(EntryNotFoundError):
            repo.update_entry("doesnotexist", username="x")
        with pytest.raises(EntryNotFoundError):
            repo.delete_entry("doesnotexist")


def test_multiple_entries_get_distinct_ids(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        a = repo.add_entry("a.com", "u1", "p1")
        b = repo.add_entry("b.com", "u2", "p2")
        assert a.id != b.id
        assert {e.id for e in repo.list_entries()} == {a.id, b.id}


def test_change_master_password_preserves_entries_and_rotates_access(tmp_path):
    path = str(tmp_path / "vault.dat")
    with VaultRepository.create(path, PW, FAST) as repo:
        entry = repo.add_entry("service", "user", "pw")
        repo.change_master_password(b"a new master password", FAST)

    with pytest.raises(VaultAuthenticationError):
        VaultRepository.open(path, PW)

    with VaultRepository.open(path, b"a new master password") as repo:
        assert repo.get_entry(entry.id).password == "pw"


def test_closed_repository_operations_fail_via_unlocked_vault(tmp_path):
    path = str(tmp_path / "vault.dat")
    repo = VaultRepository.create(path, PW, FAST)
    repo.close()
    with pytest.raises(ValueError):
        repo.add_entry("s", "u", "p")
