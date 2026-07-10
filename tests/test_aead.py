import pytest

from securevault import aead
from securevault.aead import KEY_LENGTH, TAG_LENGTH
from securevault.errors import VaultAuthenticationError

KEY = b"\x11" * KEY_LENGTH
AAD = b"authenticated header"


def test_round_trip():
    ct = aead.encrypt(KEY, b"secret data", AAD)
    assert aead.decrypt(KEY, ct.nonce, ct.blob, AAD) == b"secret data"


def test_empty_plaintext_round_trip():
    ct = aead.encrypt(KEY, b"", AAD)
    assert len(ct.blob) == TAG_LENGTH  # tag only, no ciphertext
    assert aead.decrypt(KEY, ct.nonce, ct.blob, AAD) == b""


def test_fresh_nonce_and_ciphertext_each_call():
    a = aead.encrypt(KEY, b"same plaintext", AAD)
    b = aead.encrypt(KEY, b"same plaintext", AAD)
    assert a.nonce != b.nonce
    assert a.blob != b.blob


def test_wrong_key_fails():
    ct = aead.encrypt(KEY, b"data", AAD)
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(b"\x22" * KEY_LENGTH, ct.nonce, ct.blob, AAD)


def test_tampered_ciphertext_fails():
    ct = aead.encrypt(KEY, b"data", AAD)
    blob = bytearray(ct.blob)
    blob[0] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, ct.nonce, bytes(blob), AAD)


def test_tampered_tag_fails():
    ct = aead.encrypt(KEY, b"data", AAD)
    blob = bytearray(ct.blob)
    blob[-1] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, ct.nonce, bytes(blob), AAD)


def test_tampered_nonce_fails():
    ct = aead.encrypt(KEY, b"data", AAD)
    nonce = bytearray(ct.nonce)
    nonce[0] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, bytes(nonce), ct.blob, AAD)


def test_wrong_associated_data_fails():
    ct = aead.encrypt(KEY, b"data", AAD)
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, ct.nonce, ct.blob, b"different header")


def test_malformed_nonce_length_fails_loudly():
    ct = aead.encrypt(KEY, b"data", AAD)
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, ct.nonce[:-1], ct.blob, AAD)


def test_blob_too_short_fails_loudly():
    with pytest.raises(VaultAuthenticationError):
        aead.decrypt(KEY, b"\x00" * 12, b"short", AAD)


def test_bad_key_length_is_a_programming_error():
    with pytest.raises(ValueError):
        aead.encrypt(b"short-key", b"data", AAD)
