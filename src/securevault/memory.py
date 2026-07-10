"""Best-effort erasure of secret material from memory.

Read this honestly: CPython cannot guarantee that a secret is ever removed from
memory. ``bytes`` and ``str`` are immutable and cannot be overwritten in place;
the interpreter copies objects freely; and the ``argon2-cffi`` / ``cryptography``
libraries hold keys as ``bytes`` and make internal C-level copies we cannot
reach. Memory may also be paged to swap or captured in a core dump.

The only thing we *can* overwrite is a mutable ``bytearray`` that we fully own.
``wipe`` does exactly that and nothing more. It shrinks the window in which a
secret is recoverable; it does not close it. See THREAT_MODEL.md for the full
treatment.
"""

from __future__ import annotations

import ctypes


def wipe(buffer: bytearray | None) -> None:
    """Overwrite a ``bytearray`` in place with zero bytes.

    Immutable ``bytes``/``str`` cannot be wiped and are silently ignored so that
    callers can pass either without special-casing; the limitation is real, not
    an oversight. ``None`` is accepted so cleanup paths stay simple.
    """
    if buffer is None:
        return
    if not isinstance(buffer, bytearray):
        # Immutable object: nothing we can do. Documented limitation.
        return
    length = len(buffer)
    if length == 0:
        return
    # from_buffer requires a writable buffer, which bytearray provides.
    ctypes.memset((ctypes.c_char * length).from_buffer(buffer), 0, length)
