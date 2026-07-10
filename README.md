# secure-vault

[![CI](https://github.com/AnthonyPainchaud/secure-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/AnthonyPainchaud/secure-vault/actions/workflows/ci.yml)

> **Portfolio project, not production software.** This is a demonstration of
> applied cryptography and secure-engineering practice, built to be read and
> reviewed. It has **not** had a professional security audit. Do not use it to
> store real credentials.

A local, offline, single-user password vault: a CLI that stores service
credentials in one AES-256-GCM-encrypted file, unlocked with a master password
run through Argon2id. No network calls, no cloud sync, no telemetry — the vault
never leaves the machine it's created on.

## Threat model, in brief

Full version: [THREAT_MODEL.md](THREAT_MODEL.md).

**Protects against:** an attacker who obtains the vault file itself — a stolen
laptop, a copied backup, a leaked cloud-sync folder — and tries to read or
tamper with it offline. Every field is encrypted (not just passwords: service
names, usernames, and notes too), any tampering is detected and rejected, and a
wrong password and a corrupted file produce the same generic failure so neither
leaks information.

**Does not protect against:**
- Malware, a keylogger, or any code already running on your machine while the
  vault is unlocked.
- Memory scraping of the running process, swap, or a crash dump. This is a real
  limitation of Python specifically: `str` and `bytes` are immutable, so the
  master password and derived keys **cannot be reliably wiped from memory** the
  way a lower-level language could. The implementation minimizes the exposure
  window; it cannot close it. See [THREAT_MODEL.md §6](THREAT_MODEL.md) for the
  full explanation.
- A compromised OS, coerced disclosure, or a weak master password — Argon2id
  raises the cost of guessing a password, it cannot make a guessable one safe.
- Anything after you explicitly reveal a password: terminal scrollback, shell
  history, clipboard.

If any of those are in your threat model, this tool is not sufficient.

## Security design

Full rationale, alternatives considered, and every parameter justified:
[DESIGN.md](DESIGN.md).

- **Key derivation — Argon2id** (`argon2-cffi`), 64 MiB / 3 iterations / 4 lanes
  by default (RFC 9106's memory-constrained recommendation). Chosen over PBKDF2
  (not memory-hard — cheap on GPUs) and bcrypt (not memory-hard, 72-byte input
  cap). Parameters are stored per-vault and range-checked on load so a hostile
  file can't force an oversized allocation.
- **Encryption — envelope scheme.** A random 256-bit data key (DEK) encrypts the
  vault body under **AES-256-GCM**; the DEK is itself wrapped under a
  key-encryption key derived from the master password. This means Argon2id runs
  once per unlock (not once per save), and changing the master password only
  re-wraps the DEK instead of re-encrypting all data. AES-256-GCM was chosen over
  hand-rolled encrypt-then-MAC (a classic source of composition bugs) and over
  XChaCha20-Poly1305 (stronger nonce margin, but not in the standard library
  we're using — see DESIGN.md for the tradeoff).
- **Nonces** are fresh from the OS CSPRNG on every encryption and never
  reused — the API doesn't let a caller supply one, so the most common AES-GCM
  mistake is structurally unrepresentable.
- **Integrity** is two AEAD tags covering the wrapped key and the body, with the
  file header bound in as associated data. Any tampering — ciphertext, nonce, or
  header — is rejected before any plaintext is returned.
- No cryptographic primitive is implemented by hand. Everything comes from
  `argon2-cffi` and `cryptography` (OpenSSL-backed).

## Install

Requires Python 3.10+.

```bash
git clone https://github.com/AnthonyPainchaud/secure-vault.git
cd secure-vault
python -m venv .venv && . .venv/bin/activate   # or: python -m virtualenv .venv
pip install -e .
```

(If your system Python lacks `ensurepip`/`venv`, install `virtualenv` instead:
`pip install --user virtualenv && python -m virtualenv .venv`.)

## Use

```bash
securevault init my.vault                        # create a vault (prompts for a master password)
securevault add my.vault github.com alice         # add an entry (prompts for its password)
securevault add my.vault aws.example bob --generate  # or generate one instead
securevault list my.vault                         # list entries — never prints passwords
securevault get my.vault <entry-id>                # show an entry (password masked by default)
securevault get my.vault <entry-id> --show         # reveal the password — the only command that prints it
securevault copy my.vault <entry-id>               # copy password to clipboard, auto-clear after 20s
securevault copy my.vault <entry-id> --timeout 30  # ...with a custom clear timeout
securevault update my.vault <entry-id> --username new-bob
securevault delete my.vault <entry-id>
securevault passwd my.vault                       # change the master password
securevault generate --length 24 --exclude-ambiguous  # standalone password generator
```

No secret is ever accepted as a `--flag value` (that would land in shell history
and be visible to other processes via `ps`) — passwords are always typed via a
non-echoing prompt or generated with `secrets`.

## Test

```bash
pip install -e '.[dev]'
pytest
```

143 tests covering the cryptographic core, the file format, the CRUD layer, the
CLI, clipboard auto-clear (including the "user copied something else" and
"interrupted before timeout" cases), and full create → close → reopen → retrieve
workflows, including corrupted and tampered vault files, wrong-password handling,
concurrent-access locking, and a canary check that no plaintext ever reaches disk.

## Clipboard

`securevault copy` puts a password on the system clipboard instead of printing
it, and clears it after a timeout (default 20 s), on Ctrl-C, or on `SIGTERM` — but
only if the clipboard still holds that value, so it never clobbers something you
copied in the meantime. This reduces *screen* and *dwell-time* exposure; it does
**not** protect against a process reading the clipboard during the window, does
not erase clipboard-manager history, and cannot clear if the process is killed
uncatchably. See [THREAT_MODEL.md N5.1](THREAT_MODEL.md) for the full accounting.
On Linux it requires `xclip`/`xsel` (X11) or `wl-clipboard` (Wayland); without
one, `copy` fails with a clear message and the other commands are unaffected.

## Known limitations

- **Memory is not securely wiped.** See "Does not protect against," above. This
  is the most significant limitation and is inherent to Python.
- **The clipboard is not a safe place for a secret.** `copy` shortens the window,
  but any same-user process can read the clipboard while a password is on it (see
  above / N5.1).
- **No multi-device sync.** By design — see the threat model — but it means no
  built-in way to share a vault across machines.
- **Vault-level locking, not record-level.** Two concurrent `securevault`
  invocations are serialized with a file lock rather than allowed to interleave;
  simple and correct, but means no concurrent multi-user editing.
- **No secure deletion of the old vault file on disk.** `os.replace` overwrites
  the directory entry; the previous version's ciphertext may still be
  recoverable from unallocated disk space or SSD wear-leveling until overwritten
  by something else. It is still ciphertext, so this is a minor residual risk,
  not a plaintext leak.

## What I'd do next

- Add an optional OS keychain–backed session cache so the master password isn't
  re-entered for short-lived successive commands, without weakening the
  single-unlock model.
- A machine-readable export/import path (still local-only) for migrating
  vaults, with the same JSON-only serialization discipline.
- An external audit — this codebase is small and deliberately scoped
  specifically so that one would be tractable.

## License

MIT.
