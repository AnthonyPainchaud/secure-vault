from securevault.memory import wipe


def test_wipe_zeros_a_bytearray_in_place():
    buffer = bytearray(b"super secret")
    wipe(buffer)
    assert buffer == bytearray(len(b"super secret"))
    assert set(buffer) == {0}


def test_wipe_ignores_immutable_bytes():
    # No error, and (necessarily) no effect: documented CPython limitation.
    wipe(b"cannot wipe this")


def test_wipe_accepts_none():
    wipe(None)


def test_wipe_handles_empty_bytearray():
    wipe(bytearray())
