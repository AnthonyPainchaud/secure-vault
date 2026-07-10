import pytest

from securevault.clipboard import (
    ClipboardSessionResult,
    ClipboardUnavailableError,
    clear_if_unchanged,
    copy_and_autoclear,
)


class FakeClipboard:
    """An injectable stand-in for the system clipboard.

    ``on_paste`` lets a test simulate the user (or a signal) changing the
    clipboard partway through the wait.
    """

    def __init__(self, initial: str = "") -> None:
        self.value = initial
        self.copies: list[str] = []

    def copy(self, text: str) -> None:
        self.value = text
        self.copies.append(text)

    def paste(self) -> str:
        return self.value


def _no_sleep(_seconds: float) -> None:
    return None


# -- clear_if_unchanged ------------------------------------------------


def test_clear_if_unchanged_clears_when_value_matches():
    cb = FakeClipboard("s3cret")
    assert clear_if_unchanged("s3cret", cb) is True
    assert cb.value == ""


def test_clear_if_unchanged_leaves_value_when_changed():
    cb = FakeClipboard("something the user copied")
    assert clear_if_unchanged("s3cret", cb) is False
    assert cb.value == "something the user copied"


# -- copy_and_autoclear ------------------------------------------------


def test_copies_then_clears_after_timeout():
    cb = FakeClipboard()
    slept: list[float] = []
    result = copy_and_autoclear("pw", timeout=25, backend=cb, sleep=slept.append)
    assert cb.copies[0] == "pw"       # copied first
    assert slept == [25]              # waited the requested timeout
    assert cb.value == ""            # then cleared
    assert result == ClipboardSessionResult(cleared=True, interrupted=False)


def test_does_not_clobber_a_value_the_user_copied_meanwhile():
    cb = FakeClipboard()

    def user_copies_during_wait(_seconds: float) -> None:
        cb.copy("user's own new clipboard content")

    result = copy_and_autoclear("pw", timeout=5, backend=cb, sleep=user_copies_during_wait)
    assert result.cleared is False
    assert cb.value == "user's own new clipboard content"


def test_ctrl_c_during_wait_still_clears():
    cb = FakeClipboard()

    def interrupted_sleep(_seconds: float) -> None:
        raise KeyboardInterrupt

    result = copy_and_autoclear("pw", timeout=30, backend=cb, sleep=interrupted_sleep)
    assert result.interrupted is True
    assert result.cleared is True
    assert cb.value == ""


def test_signal_raised_systemexit_during_wait_still_clears():
    cb = FakeClipboard()

    def killed_sleep(_seconds: float) -> None:
        raise SystemExit(143)

    result = copy_and_autoclear("pw", timeout=30, backend=cb, sleep=killed_sleep)
    assert result.interrupted is True
    assert result.cleared is True
    assert cb.value == ""


def test_interrupt_after_user_changed_clipboard_does_not_clobber():
    cb = FakeClipboard()

    def change_then_interrupt(_seconds: float) -> None:
        cb.copy("user content")
        raise KeyboardInterrupt

    result = copy_and_autoclear("pw", timeout=30, backend=cb, sleep=change_then_interrupt)
    assert result.interrupted is True
    assert result.cleared is False
    assert cb.value == "user content"


def test_secret_is_actually_placed_before_the_wait():
    order: list[str] = []
    cb = FakeClipboard()
    original_copy = cb.copy

    def tracking_copy(text: str) -> None:
        order.append("copy:" + ("secret" if text == "pw" else "clear"))
        original_copy(text)

    cb.copy = tracking_copy  # type: ignore[assignment]

    def sleeper(_seconds: float) -> None:
        order.append("wait")

    copy_and_autoclear("pw", timeout=1, backend=cb, sleep=sleeper)
    assert order == ["copy:secret", "wait", "copy:clear"]


def test_on_copied_runs_after_copy_and_before_wait():
    cb = FakeClipboard()
    events: list[str] = []
    copy_and_autoclear(
        "pw",
        timeout=1,
        backend=cb,
        sleep=lambda _s: events.append("wait"),
        on_copied=lambda: events.append("announced"),
    )
    assert events == ["announced", "wait"]
    assert cb.copies[0] == "pw"  # copy happened before the announcement


def test_on_copied_not_called_if_copy_fails():
    class UnavailableClipboard:
        def copy(self, text):
            raise ClipboardUnavailableError("no backend")

        def paste(self):  # pragma: no cover - never reached
            return ""

    announced = []
    with pytest.raises(ClipboardUnavailableError):
        copy_and_autoclear(
            "pw",
            timeout=1,
            backend=UnavailableClipboard(),
            sleep=_no_sleep,
            on_copied=lambda: announced.append(True),
        )
    assert announced == []  # never claimed a copy that did not happen
