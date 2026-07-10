import os

from securevault import Argon2Parameters, create, open_vault, storage

FAST = Argon2Parameters(memory_kib=19_456, time_cost=1, parallelism=1)
PW = b"disk password"


def test_write_then_read_round_trip(tmp_path):
    data = create(PW, b"disk contents", FAST)
    path = tmp_path / "vault.dat"
    storage.write_atomic(path, data)
    assert storage.read(path) == data
    with open_vault(PW, storage.read(path)) as vault:
        assert vault.read() == b"disk contents"


def test_no_plaintext_is_written_to_disk(tmp_path):
    marker = b"UNIQUE-PLAINTEXT-MARKER-4f9a2c"
    data = create(PW, marker, FAST)
    path = tmp_path / "vault.dat"
    storage.write_atomic(path, data)
    assert marker not in storage.read(path)


def test_overwrite_leaves_no_temp_files(tmp_path):
    path = tmp_path / "vault.dat"
    storage.write_atomic(path, create(PW, b"first", FAST))
    storage.write_atomic(path, create(PW, b"second", FAST))
    leftovers = [name for name in os.listdir(tmp_path) if name.startswith(".vault-")]
    assert leftovers == []
    with open_vault(PW, storage.read(path)) as vault:
        assert vault.read() == b"second"
