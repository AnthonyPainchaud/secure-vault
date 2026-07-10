import struct

import pytest

from securevault import fileformat as ff
from securevault.errors import VaultFormatError
from securevault.kdf import SALT_LENGTH, Argon2Parameters

SALT = b"\x02" * SALT_LENGTH
PARAMS = Argon2Parameters()  # defaults, in-range


def sample_file(counter: int = 7, body_blob: bytes = b"\x05" * 20) -> bytes:
    return ff.serialize(
        kdf_header=ff.build_kdf_header(PARAMS, SALT),
        counter=counter,
        dek_nonce=b"\x01" * ff.NONCE_LENGTH,
        dek_blob=b"\x02" * ff.DEK_BLOB_LENGTH,
        body_nonce=b"\x03" * ff.NONCE_LENGTH,
        body_blob=body_blob,
    )


def test_serialize_parse_round_trip():
    data = sample_file()
    parsed = ff.parse(data)
    assert parsed.params == PARAMS
    assert parsed.salt == SALT
    assert parsed.counter == 7
    assert parsed.dek_nonce == b"\x01" * ff.NONCE_LENGTH
    assert parsed.dek_blob == b"\x02" * ff.DEK_BLOB_LENGTH
    assert parsed.body_nonce == b"\x03" * ff.NONCE_LENGTH
    assert parsed.body_blob == b"\x05" * 20


def test_aad_slices_are_exact_header_bytes():
    data = sample_file()
    parsed = ff.parse(data)
    assert parsed.kdf_header == data[: ff.KDF_HEADER_LENGTH]
    assert parsed.full_header == data[: ff.FULL_HEADER_LENGTH]


def test_bad_magic_rejected():
    data = bytearray(sample_file())
    data[0:4] = b"XXXX"
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_unsupported_version_rejected():
    data = bytearray(sample_file())
    struct.pack_into("<H", data, 4, 999)
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_unsupported_kdf_id_rejected():
    data = bytearray(sample_file())
    data[6] = 9
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_unsupported_aead_id_rejected():
    data = bytearray(sample_file())
    data[7] = 9
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_out_of_range_memory_param_rejected_before_crypto():
    data = bytearray(sample_file())
    struct.pack_into("<I", data, 8, 9_999_999)  # memory_kib well above the cap
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_too_short_file_rejected():
    with pytest.raises(VaultFormatError):
        ff.parse(b"SVLT")


def test_truncated_file_rejected():
    with pytest.raises(VaultFormatError):
        ff.parse(sample_file()[:-1])


def test_trailing_garbage_rejected():
    with pytest.raises(VaultFormatError):
        ff.parse(sample_file() + b"\x00")


def test_declared_body_length_mismatch_rejected():
    data = bytearray(sample_file())
    struct.pack_into("<I", data, ff._BODY_LEN_OFFSET, 9999)
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))


def test_body_len_below_tag_size_rejected():
    data = bytearray(sample_file())
    struct.pack_into("<I", data, ff._BODY_LEN_OFFSET, 4)
    with pytest.raises(VaultFormatError):
        ff.parse(bytes(data))
