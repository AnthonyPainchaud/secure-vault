"""System clipboard integration with auto-clear (application layer).

This is a security feature first and a convenience second. A password on the
clipboard is readable by any process running as the same user on essentially
every OS, so the goal is not to make the clipboard safe -- it is to keep the
secret there for as short a time as possible and to remove it as reliably as the
platform allows. See THREAT_MODEL.md for the exact properties and their limits.

Design notes:

- The clear runs from a ``finally`` block, so it fires on normal completion and
  on Ctrl-C / a signal-raised exception during the wait. It cannot fire if the
  process is ``SIGKILL``ed or the machine loses power -- in those cases the
  secret stays on the clipboard.
- We only clear the clipboard if it *still holds our value*. If the user copied
  something else during the wait, we leave their copy untouched.
- The backend is injectable so the auto-clear logic can be tested without a real
  system clipboard (and so this module imports safely on a headless machine).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

import pyperclip

from .errors import VaultError

DEFAULT_TIMEOUT_SECONDS = 20


class ClipboardUnavailableError(VaultError):
    """No working system clipboard backend is available.

    On Linux this usually means neither ``xclip``/``xsel`` (X11) nor
    ``wl-clipboard`` (Wayland) is installed.
    """


class ClipboardBackend(Protocol):
    def copy(self, text: str) -> None: ...
    def paste(self) -> str: ...


class PyperclipBackend:
    """The real backend, delegating to pyperclip.

    pyperclip picks a platform mechanism itself (pbcopy/pbpaste on macOS, the
    Win32 API via ctypes on Windows, xclip/xsel/wl-clipboard on Linux). Using it
    rather than shelling out ourselves means we do not hand-maintain that
    platform matrix; the tradeoff is that on Linux it still requires one of those
    helper binaries to be installed.
    """

    def copy(self, text: str) -> None:
        try:
            pyperclip.copy(text)
        except pyperclip.PyperclipException as exc:
            raise ClipboardUnavailableError(str(exc)) from exc

    def paste(self) -> str:
        try:
            return pyperclip.paste()
        except pyperclip.PyperclipException as exc:
            raise ClipboardUnavailableError(str(exc)) from exc


@dataclass(frozen=True)
class ClipboardSessionResult:
    #: True if we cleared the clipboard; False if its contents had changed and we
    #: deliberately left them alone.
    cleared: bool
    #: True if the wait was cut short by Ctrl-C or a signal rather than the full
    #: timeout elapsing.
    interrupted: bool


def clear_if_unchanged(expected: str, backend: ClipboardBackend) -> bool:
    """Clear the clipboard only if it still holds ``expected``.

    Returns True if we cleared it, False if the contents had changed (the user
    copied something else) and we left them untouched.
    """
    if backend.paste() != expected:
        return False
    backend.copy("")
    return True


def copy_and_autoclear(
    secret: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    backend: ClipboardBackend | None = None,
    sleep: Callable[[float], None] = time.sleep,
    on_copied: Callable[[], None] | None = None,
) -> ClipboardSessionResult:
    """Copy ``secret`` to the clipboard, hold for ``timeout`` seconds, then clear.

    The clear is in a ``finally`` so it runs whether the wait completes normally,
    is interrupted by Ctrl-C, or is cut short by a signal handler that raises. It
    clears only if the clipboard still holds ``secret`` (see
    :func:`clear_if_unchanged`). Raises :class:`ClipboardUnavailableError` if the
    initial copy fails because no backend is available -- in which case
    ``on_copied`` is never called, so a caller cannot announce a copy that did not
    happen. ``on_copied`` runs exactly once, after a successful copy and before
    the wait, for the caller to notify the user.
    """
    backend = backend or PyperclipBackend()
    backend.copy(secret)  # may raise ClipboardUnavailableError before we wait
    if on_copied is not None:
        on_copied()
    interrupted = False
    try:
        try:
            sleep(timeout)
        except (KeyboardInterrupt, SystemExit):
            interrupted = True
    finally:
        cleared = clear_if_unchanged(secret, backend)
    return ClipboardSessionResult(cleared=cleared, interrupted=interrupted)
