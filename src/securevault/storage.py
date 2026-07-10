"""Reading and writing the encrypted vault file on disk.

Only ciphertext is ever written. Writes are atomic: the new contents go to a
temporary file in the same directory, are flushed and fsync'd, and then replace
the target with ``os.replace`` (an atomic rename on POSIX and Windows). A crash
at any point leaves either the complete old file or the complete new one -- never
a truncated or partially written vault, and never a plaintext artifact.

The file is created owner-read/write only (0600). This is defense in depth --
the contents are ciphertext -- but it avoids advertising the vault's existence
and size to other local users any more than necessary. ``os.replace`` transfers
the temp file's inode (and therefore its 0600 mode) onto the target, so the mode
is enforced on every write regardless of the previous file's permissions.
"""

from __future__ import annotations

import os
import stat
import tempfile

#: Permission bits for the vault file: owner read/write only.
VAULT_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def read(path: str | os.PathLike) -> bytes:
    """Read the raw vault bytes from ``path``."""
    with open(path, "rb") as handle:
        return handle.read()


def write_atomic(path: str | os.PathLike, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` with 0600 permissions.

    ``data`` must already be the serialized, encrypted vault; this function never
    sees or writes plaintext.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
        # mkstemp already creates the file 0600; set it explicitly so the
        # guarantee does not depend on that implementation detail. fchmod is
        # POSIX-only; mkstemp's own 0600 stands in where it is unavailable.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, VAULT_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _fsync_directory(directory)
    except BaseException:
        # Best-effort cleanup so a failed write does not leave a temp file behind.
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _fsync_directory(directory: str) -> None:
    """fsync the directory so the rename itself is durable."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return  # not all platforms allow opening a directory; skip silently
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)
