# Security Review (Stage 4 hardening pass)

An adversarial self-review of the implementation against
[THREAT_MODEL.md](THREAT_MODEL.md) and [DESIGN.md](DESIGN.md). It records what was
verified as holding, what fell short and was fixed, and -- most importantly --
what cannot be fully mitigated and why.

## Method

Every module was re-read looking specifically for: plaintext reaching disk / logs
/ temp files, secrets living longer than necessary, non-constant-time comparison
of secrets, information-leaking errors, unsafe file permissions, and failure
paths that could corrupt the vault or lose data.

---

## Verified holding (no change needed)

- **No plaintext to disk.** `storage.write_atomic` only ever receives the
  serialized *ciphertext*; the temp file it writes contains ciphertext, and it is
  atomically `os.replace`d into place. A canary test writes known plaintext
  markers (password, notes, service, username) through the full stack and asserts
  none appear in the on-disk bytes -- confirming even metadata is encrypted.
- **No logging of secrets.** The codebase has no logging framework and no
  `print`; the only output is via `click.echo` on explicit user commands.
- **Wrong password is indistinguishable from tampering.** Both raise
  `VaultAuthenticationError` with an identical, generic message; the AEAD tag
  check (constant-time, in `cryptography`) is the only arbiter, and the full
  Argon2id cost is always paid before it. Tests assert the two messages are
  byte-identical and leak neither the password nor the plaintext.
- **KDF-parameter DoS guard.** Out-of-range Argon2 parameters in a hostile header
  are rejected in `fileformat.parse` *before* any allocation or derivation.
- **Atomic writes prevent on-disk corruption.** A crash or failed write leaves
  either the complete old vault or the complete new one; never a torn file.

---

## Findings fixed in this pass

### F1 — Concurrent writers could silently lose data (was: unimplemented)
DESIGN.md failure mode #11 ("concurrent access is refused, not raced") had no
implementation. Two invocations could both open the vault, mutate independently,
and the second atomic replace would discard the first's changes.

**Fix:** `locking.FileLock` takes an exclusive, non-blocking `flock` on a sidecar
`<vault>.lock` file, acquired before the vault is read and held for the whole
session. A second process is refused with `VaultLockedError` rather than racing.
The lock is on a sidecar (not the vault) because atomic replace swaps the vault's
inode on every write. Verified cross-process, not just in-process.

### F2 — Vault file permissions were implicit
`mkstemp` happens to create files as `0600` and `os.replace` preserves that, so
the vault *was* owner-only -- but nothing enforced or asserted it.

**Fix:** `write_atomic` now `fchmod`s the file to `0600` explicitly
(`storage.VAULT_FILE_MODE`), with a test asserting the on-disk mode. This is
defense in depth (contents are ciphertext) but avoids exposing the vault's
existence/size to other local users.

### F3 — Decrypted entries lingered after close
`VaultRepository` held the decrypted `Entry` objects for its lifetime and did not
drop them on `close()`.

**Fix:** `close()` now clears the entry list (in addition to wiping the DEK and
plaintext `bytearray`s in the crypto core). The `str` fields still cannot be
wiped (see R1), but dropping references lets the GC reclaim them promptly.

### F4 — Secret comparisons used `==`
The master-password and entry-password confirmation prompts compared with `!=`.
These are the user's own two inputs, not an attacker-observable oracle, so this
was not a real timing vulnerability -- but it left `==`-on-secrets in the code.

**Fix:** both now use `hmac.compare_digest` on the UTF-8-encoded values
(`_passwords_match`). Comparing the encoded bytes also avoids a real bug:
`hmac.compare_digest` on a non-ASCII `str` raises `TypeError`. No home-grown
comparison exists anywhere in the cryptographic path -- tag verification is left
entirely to the library.

---

## Cannot be fully mitigated (documented, not fixed)

### R1 — Secrets cannot be reliably erased from memory (the big one)
This is a property of CPython, restated honestly (see also THREAT_MODEL.md §6):

- `getpass.getpass()` returns the master password as an immutable `str` that can
  never be overwritten.
- `Entry` passwords/usernames/notes are `str`; the serialized body and the keys
  returned by `argon2-cffi` / held by `cryptography` are immutable `bytes`. None
  of these can be wiped, and the interpreter may copy them freely.
- We do what the language allows: the DEK and decrypted-body `bytearray`s are
  overwritten on close, references are dropped, and the unlocked window is one
  short CLI command. This **shrinks** the exposure window; it does not close it.

The consequence: an attacker who can read this process's memory, or recover swap
/ a core dump, may recover secrets. That is exactly the N1–N3 out-of-scope set,
and this tool does not defend against it. We do not claim otherwise.

### R2 — `getpass` echoes the password when stdin is not a TTY
If input is piped/redirected, `getpass` falls back to reading from a stream and
prints a `GetPassWarning`; the typed characters may be echoed. On an interactive
terminal (the intended use) there is no echo. This is stdlib behavior we do not
override; scripted/piped use is the user's explicit choice.

### R3 — TOCTOU on `create`'s "refuse to overwrite" check
`VaultRepository.create` checks `os.path.exists` and then writes; a file created
in between would be clobbered by the atomic replace. For a single-user, local
tool the race is negligible, and the lock (F1) further narrows it. Not treated as
a real threat.

### R4 — In-memory state can advance past disk on a failed write
If `write_atomic` fails (e.g. disk full) mid-command, the in-memory repository has
already applied the mutation while the on-disk file is unchanged. The **on-disk
vault is never corrupted** (atomic replace guarantees old-or-new). Because each
CLI invocation is a single open/mutate/close, the divergent in-memory state is
discarded on exit and the next run reads the last good file. For long-lived
library use, callers should treat a failed mutation as "reopen the vault."

### R5 — Rollback / availability (THREAT_MODEL N7)
An attacker who can write the file can replace it with an older, legitimately
signed version (reverting a change) or simply delete it. Detecting rollback needs
trusted external state a single offline file cannot provide; availability is not
a cryptographic property. Mitigation remains user-side backups. Unchanged from
the threat model; restated here so it is not mistaken for an oversight.

---

## Checklist from the review brief

| Asked to check | Result |
|---|---|
| Plaintext to disk / logs / temp files | None found; canary test added (verified) |
| Secrets lingering in memory | Minimized (F3, `bytearray` wipes); hard limit documented (R1) |
| Timing-sensitive comparisons | `hmac.compare_digest` everywhere relevant (F4); AEAD tag check is library constant-time |
| Info-leaking error messages | Wrong-password/tamper unified; structural errors are password-independent |
| Unsafe vault file permissions | Enforced `0600` + test (F2) |
| Failure paths that corrupt the vault | Atomic writes; concurrency lock added (F1); divergence is benign (R4) |
