"""Entry model and JSON (de)serialization for the vault body.

The vault body plaintext is a JSON document -- never pickle/marshal/yaml/eval
(see DESIGN.md, "places where a naive implementation introduces a real
vulnerability"). This module is the only place that (de)serializes it; the
cryptographic core treats the body as opaque bytes and never imports this
module.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .errors import VaultFormatError

_SCHEMA_VERSION = 1


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_entry_id() -> str:
    """A short, human-typeable identifier. Not a security boundary -- entries
    are only reachable after the vault itself has been unlocked."""
    return uuid.uuid4().hex[:8]


@dataclass
class Entry:
    id: str
    service: str
    username: str
    password: str
    notes: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Entry":
        try:
            return Entry(
                id=str(data["id"]),
                service=str(data["service"]),
                username=str(data["username"]),
                password=str(data["password"]),
                notes=str(data.get("notes", "")),
                created_at=str(data["created_at"]),
                updated_at=str(data["updated_at"]),
            )
        except KeyError as exc:
            raise VaultFormatError(f"malformed entry: missing field {exc}") from exc


def serialize_entries(entries: list[Entry]) -> bytes:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "entries": [e.to_dict() for e in entries],
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def deserialize_entries(data: bytes) -> list[Entry]:
    """Parse the vault body. Raises VaultFormatError on any structural problem.

    By the time this runs, ``data`` has already passed AEAD authentication, so a
    parse failure here means a bug (e.g. a schema change), not an attack -- an
    attacker cannot produce ciphertext that decrypts to attacker-chosen bytes
    without the key. We still parse defensively and raise our own error type
    rather than let a raw JSONDecodeError escape.
    """
    try:
        payload = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise VaultFormatError("vault body is not valid JSON") from exc

    if not isinstance(payload, dict) or "entries" not in payload:
        raise VaultFormatError("vault body missing 'entries'")
    if payload.get("schema_version") != _SCHEMA_VERSION:
        raise VaultFormatError(
            f"unsupported entry schema version {payload.get('schema_version')!r}"
        )
    raw_entries = payload["entries"]
    if not isinstance(raw_entries, list):
        raise VaultFormatError("vault body 'entries' must be a list")
    return [Entry.from_dict(e) for e in raw_entries]
