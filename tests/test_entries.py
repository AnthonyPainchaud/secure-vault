import json

import pytest

from securevault.entries import Entry, deserialize_entries, new_entry_id, serialize_entries
from securevault.errors import VaultFormatError


def make_entry(**overrides) -> Entry:
    defaults = dict(
        id="abc12345",
        service="github.com",
        username="alice",
        password="hunter2",
        notes="",
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
    )
    defaults.update(overrides)
    return Entry(**defaults)


def test_round_trip_preserves_fields():
    entries = [make_entry(), make_entry(id="def67890", service="example.com", notes="backup codes: 123")]
    data = serialize_entries(entries)
    restored = deserialize_entries(data)
    assert restored == entries


def test_empty_list_round_trip():
    assert deserialize_entries(serialize_entries([])) == []


def test_serialized_body_is_json_not_pickle():
    data = serialize_entries([make_entry()])
    payload = json.loads(data.decode("utf-8"))  # must not raise
    assert payload["entries"][0]["service"] == "github.com"


def test_new_entry_id_is_short_and_unique_enough():
    ids = {new_entry_id() for _ in range(1000)}
    assert len(ids) == 1000
    assert all(len(i) == 8 for i in ids)


def test_malformed_json_rejected():
    with pytest.raises(VaultFormatError):
        deserialize_entries(b"not json at all")


def test_non_utf8_bytes_rejected():
    with pytest.raises(VaultFormatError):
        deserialize_entries(b"\xff\xfe\x00\x01")


def test_missing_entries_key_rejected():
    with pytest.raises(VaultFormatError):
        deserialize_entries(json.dumps({"schema_version": 1}).encode())


def test_wrong_schema_version_rejected():
    with pytest.raises(VaultFormatError):
        deserialize_entries(json.dumps({"schema_version": 99, "entries": []}).encode())


def test_entries_not_a_list_rejected():
    with pytest.raises(VaultFormatError):
        deserialize_entries(json.dumps({"schema_version": 1, "entries": "nope"}).encode())


def test_entry_missing_required_field_rejected():
    payload = {
        "schema_version": 1,
        "entries": [{"id": "x", "service": "s", "username": "u", "password": "p"}],
    }
    with pytest.raises(VaultFormatError):
        deserialize_entries(json.dumps(payload).encode())
