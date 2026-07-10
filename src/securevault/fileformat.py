"""On-disk vault container: byte layout, serialization, and bounds-checked parsing.

Layout (all integers little-endian, all lengths fixed or explicitly prefixed)::

    offset  size  field
    0       4     magic          b"SVLT"
    4       2     version        uint16
    6       1     kdf_id         uint8   (1 = Argon2id)
    7       1     aead_id        uint8   (1 = AES-256-GCM)
    8       4     argon2_m       uint32  (KiB)
    12      4     argon2_t       uint32
    16      4     argon2_p       uint32
    20      16    salt
    --- bytes[0:36] = KDF header, bound as AAD over the wrapped DEK ---
    36      8     save_counter   uint64
    --- bytes[0:44] = full header, bound as AAD over the body ---
    44      12    dek_nonce
    56      48    dek_blob       wrapped DEK (32-byte ciphertext || 16-byte tag)
    104     12    body_nonce
    116     4     body_len       uint32  (length of body_blob)
    120     N     body_blob      body ciphertext || 16-byte tag

The header is authenticated but not encrypted. The two AAD scopes are chosen so
that a normal save (which changes only the body and the counter) does not have to
re-wrap the DEK: the DEK wrap is bound to the KDF header (no counter), while the
body is bound to the full header (with counter). Every header byte is therefore
covered by at least one authentication tag.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .aead import NONCE_LENGTH, TAG_LENGTH
from .errors import VaultFormatError
from .kdf import SALT_LENGTH, Argon2Parameters

MAGIC = b"SVLT"
FORMAT_VERSION = 1
KDF_ARGON2ID = 1
AEAD_AES256GCM = 1

DEK_LENGTH = 32
DEK_BLOB_LENGTH = DEK_LENGTH + TAG_LENGTH  # 48

# Field offsets derived from the layout above.
_KDF_HEADER_STRUCT = struct.Struct("<4sHBBIII16s")  # 36 bytes
KDF_HEADER_LENGTH = _KDF_HEADER_STRUCT.size          # 36
_COUNTER_STRUCT = struct.Struct("<Q")                # 8 bytes
FULL_HEADER_LENGTH = KDF_HEADER_LENGTH + _COUNTER_STRUCT.size  # 44

_DEK_NONCE_OFFSET = FULL_HEADER_LENGTH               # 44
_DEK_BLOB_OFFSET = _DEK_NONCE_OFFSET + NONCE_LENGTH  # 56
_BODY_NONCE_OFFSET = _DEK_BLOB_OFFSET + DEK_BLOB_LENGTH  # 104
_BODY_LEN_OFFSET = _BODY_NONCE_OFFSET + NONCE_LENGTH  # 116
_BODY_OFFSET = _BODY_LEN_OFFSET + 4                   # 120

#: Smallest possible valid file: fixed prefix + an empty body (tag only).
MIN_FILE_LENGTH = _BODY_OFFSET + TAG_LENGTH           # 136


def build_kdf_header(params: Argon2Parameters, salt: bytes) -> bytes:
    """Serialize the 36-byte KDF header (bytes[0:36])."""
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")
    return _KDF_HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        KDF_ARGON2ID,
        AEAD_AES256GCM,
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        salt,
    )


def build_full_header(params: Argon2Parameters, salt: bytes, counter: int) -> bytes:
    """Serialize the 44-byte full header (KDF header || save_counter)."""
    if counter < 0 or counter > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("save_counter out of uint64 range")
    return build_kdf_header(params, salt) + _COUNTER_STRUCT.pack(counter)


def serialize(
    kdf_header: bytes,
    counter: int,
    dek_nonce: bytes,
    dek_blob: bytes,
    body_nonce: bytes,
    body_blob: bytes,
) -> bytes:
    """Assemble a complete vault file from its already-encrypted parts."""
    if len(kdf_header) != KDF_HEADER_LENGTH:
        raise ValueError("bad kdf_header length")
    if len(dek_nonce) != NONCE_LENGTH or len(body_nonce) != NONCE_LENGTH:
        raise ValueError("bad nonce length")
    if len(dek_blob) != DEK_BLOB_LENGTH:
        raise ValueError("bad dek_blob length")
    if len(body_blob) < TAG_LENGTH:
        raise ValueError("body_blob too short to contain a tag")
    return b"".join(
        (
            kdf_header,
            _COUNTER_STRUCT.pack(counter),
            dek_nonce,
            dek_blob,
            body_nonce,
            struct.pack("<I", len(body_blob)),
            body_blob,
        )
    )


@dataclass(frozen=True)
class ParsedVaultFile:
    """The structurally validated fields of a vault file.

    ``kdf_header`` and ``full_header`` are the exact bytes as read, so they can
    be fed back as associated data; any tampering with header fields therefore
    changes the AAD and fails authentication.
    """

    params: Argon2Parameters
    salt: bytes
    counter: int
    kdf_header: bytes
    full_header: bytes
    dek_nonce: bytes
    dek_blob: bytes
    body_nonce: bytes
    body_blob: bytes


def parse(data: bytes) -> ParsedVaultFile:
    """Parse and structurally validate a vault file.

    Every length is checked against the actual size of ``data`` before it is
    used, and the KDF parameters are range-checked, all before any cryptographic
    work. Raises :class:`VaultFormatError` on any structural problem.
    """
    if len(data) < MIN_FILE_LENGTH:
        raise VaultFormatError(
            f"file too short: {len(data)} < minimum {MIN_FILE_LENGTH}"
        )

    magic, version, kdf_id, aead_id, m, t, p, salt = _KDF_HEADER_STRUCT.unpack(
        data[:KDF_HEADER_LENGTH]
    )
    if magic != MAGIC:
        raise VaultFormatError("bad magic: not a vault file")
    if version != FORMAT_VERSION:
        raise VaultFormatError(f"unsupported format version {version}")
    if kdf_id != KDF_ARGON2ID:
        raise VaultFormatError(f"unsupported kdf id {kdf_id}")
    if aead_id != AEAD_AES256GCM:
        raise VaultFormatError(f"unsupported aead id {aead_id}")

    params = Argon2Parameters(memory_kib=m, time_cost=t, parallelism=p)
    params.validate()  # raises VaultFormatError before any allocation/derivation

    (counter,) = _COUNTER_STRUCT.unpack(
        data[KDF_HEADER_LENGTH:FULL_HEADER_LENGTH]
    )
    dek_nonce = data[_DEK_NONCE_OFFSET:_DEK_BLOB_OFFSET]
    dek_blob = data[_DEK_BLOB_OFFSET:_BODY_NONCE_OFFSET]
    body_nonce = data[_BODY_NONCE_OFFSET:_BODY_LEN_OFFSET]
    (body_len,) = struct.unpack("<I", data[_BODY_LEN_OFFSET:_BODY_OFFSET])

    if body_len < TAG_LENGTH:
        raise VaultFormatError("body_len too small to contain a tag")
    if _BODY_OFFSET + body_len != len(data):
        # Reject truncation and any trailing bytes: the declared body length must
        # account for exactly the remainder of the file.
        raise VaultFormatError("declared body length does not match file size")
    body_blob = data[_BODY_OFFSET:]

    return ParsedVaultFile(
        params=params,
        salt=salt,
        counter=counter,
        kdf_header=data[:KDF_HEADER_LENGTH],
        full_header=data[:FULL_HEADER_LENGTH],
        dek_nonce=dek_nonce,
        dek_blob=dek_blob,
        body_nonce=body_nonce,
        body_blob=body_blob,
    )
