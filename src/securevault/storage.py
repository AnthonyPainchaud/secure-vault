"""Reading and writing the encrypted vault file on disk.

Only ciphertext is ever written. Writes are atomic: the new contents go to a
temporary file in the same directory, are flushed and fsync'd, and then replace
the target with ``os.replace`` (an atomic rename on POSIX and Windows). A crash
at any point leaves either the complete old file or the complete new one -- never
a truncated or partially written vault, and never a plaintext artifact.
"""

from __future__ import annotations

import os
import tempfile


def read(path: str | os.PathLike) -> bytes:
    """Read the raw vault bytes from ``path``."""
    with open(path, "rb") as handle:
        return handle.read()


def write_atomic(path: str | os.PathLike, data: bytes) -> None:
    """Atomically write ``data`` to ``path``.

    ``data`` must already be the serialized, encrypted vault; this function never
    sees or writes plaintext.
    """
    path = os.fspath(path)
    directory = os.path.dirname(os.path.abspath(path))

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
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
