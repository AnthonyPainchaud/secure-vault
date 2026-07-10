"""Advisory inter-process locking for the vault.

A single-user tool still needs to stop two of its *own* invocations from writing
the same vault concurrently: both would open the old file, mutate independently,
and the second atomic replace would silently discard the first one's changes (a
lost update). This module takes an exclusive, non-blocking advisory lock so the
second process fails loudly instead.

The lock is held on a sidecar ``<vault>.lock`` file rather than on the vault
itself, because ``storage.write_atomic`` replaces the vault's inode on every
write, which would drop a lock held on the old inode. The sidecar's inode is
stable for the session.

Locking uses ``fcntl.flock`` (POSIX). On a platform without ``fcntl`` the lock
degrades to a no-op; that limitation is documented in SECURITY_REVIEW.md rather
than hidden.
"""

from __future__ import annotations

import os

from .errors import VaultLockedError

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only on non-POSIX platforms
    fcntl = None


class FileLock:
    """An exclusive, non-blocking advisory lock tied to a vault path."""

    def __init__(self, vault_path: str | os.PathLike) -> None:
        self._lock_path = os.fspath(vault_path) + ".lock"
        self._fd: int | None = None

    def acquire(self) -> None:
        if fcntl is None:
            return  # best-effort no-op; see module docstring / SECURITY_REVIEW.md
        fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise VaultLockedError(
                f"{self._lock_path[:-5]} is locked by another process"
            ) from exc
        self._fd = fd

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
