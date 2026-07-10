# secure-vault

A local, offline, single-user password vault. The design goal is a small,
correct, honestly-scoped cryptographic core rather than a large feature set.

- **Threat model:** [THREAT_MODEL.md](THREAT_MODEL.md) — what this protects
  against and, just as importantly, what it does not.
- **Cryptographic design:** [DESIGN.md](DESIGN.md) — every choice justified
  against its alternatives.

## Status

Cryptographic core only: Argon2id key derivation, AES-256-GCM authenticated
encryption, the on-disk container format, and the envelope
create / open / save / change-password flow. There is no CLI and no entry model
yet; the vault body is treated as opaque bytes.

## Cryptographic core at a glance

- **Key derivation:** Argon2id (`argon2-cffi`), default 64 MiB / t=3 / p=4,
  parameters stored per-vault and range-checked on load.
- **Encryption:** envelope scheme — a random 256-bit data key (DEK) encrypts the
  body under AES-256-GCM; the DEK is wrapped under a key-encryption key derived
  from the master password. Fresh random nonce per encryption; the header is
  bound as associated data.
- **Integrity:** two AEAD tags; any change to ciphertext, nonce, or header fails
  authentication loudly, and a wrong password is indistinguishable from tampering.

## Development

```bash
python -m virtualenv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
```

## Layout

```
src/securevault/
  kdf.py         Argon2id key derivation and parameter bounds
  aead.py        AES-256-GCM wrapper (nonce generated internally)
  fileformat.py  byte layout, serialization, bounds-checked parsing
  vault.py       envelope create / open / save / change-password
  storage.py     atomic, ciphertext-only file I/O
  memory.py      best-effort secret wiping (see THREAT_MODEL.md for limits)
  errors.py      exception hierarchy
tests/           pytest suite, including the security-relevant cases
```

## License

MIT.
