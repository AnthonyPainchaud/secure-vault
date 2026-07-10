import pytest

from securevault import (
    Argon2Parameters,
    VaultAuthenticationError,
    create,
    open_vault,
)
from securevault import fileformat as ff

FAST = Argon2Parameters(memory_kib=19_456, time_cost=1, parallelism=1)
PW = b"correct horse battery staple"


def test_correct_password_decrypts():
    data = create(PW, b"my secret vault contents", FAST)
    with open_vault(PW, data) as vault:
        assert vault.read() == b"my secret vault contents"


@pytest.mark.parametrize(
    "payload",
    [b"", b"x", b"\x00\x01\x02\xff", b"A" * 10_000, bytes(range(256))],
)
def test_round_trip_preserves_data_exactly(payload):
    data = create(PW, payload, FAST)
    with open_vault(PW, data) as vault:
        assert vault.read() == payload


def test_wrong_password_fails():
    data = create(PW, b"contents", FAST)
    with pytest.raises(VaultAuthenticationError):
        open_vault(b"wrong password", data)


def test_wrong_password_and_tampering_are_indistinguishable():
    data = create(PW, b"the real contents", FAST)

    with pytest.raises(VaultAuthenticationError) as wrong_pw:
        open_vault(b"guess", data)

    tampered = bytearray(data)
    tampered[-1] ^= 0x01
    with pytest.raises(VaultAuthenticationError) as tamper:
        open_vault(PW, bytes(tampered))

    # Same message for both causes: a caller cannot tell them apart.
    assert str(wrong_pw.value) == str(tamper.value)
    # And the error never echoes the guessed password or the plaintext.
    assert b"guess" not in str(wrong_pw.value).encode()
    assert b"contents" not in str(tamper.value).encode()


def test_tampered_body_ciphertext_fails():
    data = bytearray(create(PW, b"contents here", FAST))
    data[ff._BODY_OFFSET] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_body_tag_fails():
    data = bytearray(create(PW, b"contents", FAST))
    data[-1] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_salt_fails():
    data = bytearray(create(PW, b"contents", FAST))
    data[20] ^= 0x01  # first salt byte
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_dek_nonce_fails():
    data = bytearray(create(PW, b"contents", FAST))
    data[ff._DEK_NONCE_OFFSET] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_dek_blob_fails():
    data = bytearray(create(PW, b"contents", FAST))
    data[ff._DEK_BLOB_OFFSET] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_body_nonce_fails():
    data = bytearray(create(PW, b"contents", FAST))
    data[ff._BODY_NONCE_OFFSET] ^= 0x01
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_tampered_counter_fails_via_body_aad():
    # The counter is not part of the DEK-wrap AAD, so the DEK still unwraps; it
    # is part of the body AAD, so the body authentication must fail.
    data = bytearray(create(PW, b"contents", FAST))
    data[ff.KDF_HEADER_LENGTH] ^= 0x01  # first counter byte, at offset 36
    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, bytes(data))


def test_save_updates_contents_and_increments_counter():
    data = create(PW, b"v1", FAST)
    with open_vault(PW, data) as vault:
        assert vault.save_counter == 0
        data2 = vault.save(b"v2 contents")
        assert vault.save_counter == 1
        assert vault.read() == b"v2 contents"

    with open_vault(PW, data2) as reopened:
        assert reopened.read() == b"v2 contents"
        assert reopened.save_counter == 1


def test_change_password_preserves_data_and_invalidates_old_password():
    data = create(PW, b"secret", FAST)
    with open_vault(PW, data) as vault:
        new_data = vault.change_password(b"a brand new password", FAST)

    with pytest.raises(VaultAuthenticationError):
        open_vault(PW, new_data)

    with open_vault(b"a brand new password", new_data) as vault:
        assert vault.read() == b"secret"


def test_closed_vault_rejects_use():
    vault = open_vault(PW, create(PW, b"secret", FAST))
    vault.close()
    with pytest.raises(ValueError):
        vault.read()


def test_default_parameters_round_trip():
    # Exercise the real (slow) default parameters at least once.
    data = create(PW, b"defaults", Argon2Parameters())
    with open_vault(PW, data) as vault:
        assert vault.read() == b"defaults"
