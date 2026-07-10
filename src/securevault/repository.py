"""Entry CRUD on top of the cryptographic core.

This module is the only bridge between `securevault.vault` (which knows only
about opaque plaintext bytes) and the `Entry` model. It never touches the file
format or cryptographic primitives directly -- it calls `vault.create`,
`vault.open_vault`, `UnlockedVault.save`, and `UnlockedVault.change_password`,
and leaves everything below that line untouched.

Every mutation is persisted immediately with an atomic write (write-through),
so there is no unsaved in-memory state that could be lost between commands --
each CLI invocation is a single open/mutate/close cycle.
"""

from __future__ import annotations

import os
from dataclasses import replace

from . import storage, vault
from .entries import Entry, deserialize_entries, new_entry_id, now_iso, serialize_entries
from .errors import VaultError
from .kdf import Argon2Parameters


class EntryNotFoundError(VaultError):
    def __init__(self, entry_id: str) -> None:
        super().__init__(f"no entry with id {entry_id!r}")
        self.entry_id = entry_id


class VaultRepository:
    def __init__(self, path: str, unlocked: vault.UnlockedVault) -> None:
        self._path = path
        self._unlocked = unlocked
        self._entries: list[Entry] = deserialize_entries(unlocked.read())
        self._closed = False

    @classmethod
    def create(
        cls,
        path: str,
        master_password: bytes,
        params: Argon2Parameters | None = None,
    ) -> "VaultRepository":
        """Create a brand-new, empty vault file at ``path``.

        Refuses to overwrite an existing file -- callers that want to replace a
        vault must remove it explicitly first, so this can never silently
        clobber the user's existing data.
        """
        if os.path.exists(path):
            raise FileExistsError(f"{path} already exists")
        data = vault.create(master_password, serialize_entries([]), params)
        storage.write_atomic(path, data)
        unlocked = vault.open_vault(master_password, data)
        return cls(path, unlocked)

    @classmethod
    def open(cls, path: str, master_password: bytes) -> "VaultRepository":
        data = storage.read(path)
        unlocked = vault.open_vault(master_password, data)
        return cls(path, unlocked)

    # -- queries --------------------------------------------------------

    def list_entries(self) -> list[Entry]:
        return list(self._entries)

    def get_entry(self, entry_id: str) -> Entry:
        for entry in self._entries:
            if entry.id == entry_id:
                return entry
        raise EntryNotFoundError(entry_id)

    # -- mutations --------------------------------------------------------

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> Entry:
        entry = Entry(id=new_entry_id(), service=service, username=username, password=password, notes=notes)
        while any(existing.id == entry.id for existing in self._entries):
            entry = replace(entry, id=new_entry_id())  # astronomically unlikely
        self._entries.append(entry)
        self._persist()
        return entry

    def update_entry(
        self,
        entry_id: str,
        *,
        service: str | None = None,
        username: str | None = None,
        password: str | None = None,
        notes: str | None = None,
    ) -> Entry:
        """Update only the fields passed as non-None; everything else is unchanged."""
        current = self.get_entry(entry_id)
        updated = replace(
            current,
            service=current.service if service is None else service,
            username=current.username if username is None else username,
            password=current.password if password is None else password,
            notes=current.notes if notes is None else notes,
            updated_at=now_iso(),
        )
        self._entries[self._entries.index(current)] = updated
        self._persist()
        return updated

    def delete_entry(self, entry_id: str) -> None:
        entry = self.get_entry(entry_id)
        self._entries.remove(entry)
        self._persist()

    def change_master_password(self, new_password: bytes, params: Argon2Parameters | None = None) -> None:
        data = self._unlocked.change_password(new_password, params)
        storage.write_atomic(self._path, data)

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        if self._closed:
            return
        self._unlocked.close()
        self._closed = True

    def __enter__(self) -> "VaultRepository":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internal --------------------------------------------------------

    def _persist(self) -> None:
        data = self._unlocked.save(serialize_entries(self._entries))
        storage.write_atomic(self._path, data)
