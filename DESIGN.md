# Cryptographic Design — Secure Vault

**Status:** Stage 1 (design). No implementation exists yet.
**Companion:** see `THREAT_MODEL.md` for scope. This document justifies every
cryptographic choice against its alternatives and lists the concrete failure
modes the implementation must defend against.

Guiding rule: **we implement no cryptographic primitive by hand.** Every
primitive comes from a vetted library (`argon2-cffi`, `cryptography`). The code we
write is *composition and plumbing* — and composition is exactly where password
managers usually get broken, so that plumbing is specified carefully below.

---

## 1. Overview of the scheme (envelope encryption)

We use a two-key **envelope (key-wrapping)** design rather than encrypting the
vault directly under the password-derived key.

```
  master password ──Argon2id(salt, params)──►  KEK  (key-encryption key, 256-bit)
                                                 │
                                                 │ AEAD-wrap
                                                 ▼
  random DEK (data key, 256-bit) ──────────►  wrapped DEK  (stored in file)
        │
        │ AEAD-encrypt(nonce)
        ▼
  vault plaintext (JSON of entries) ───────►  ciphertext + tag  (stored in file)
```

- **KEK** = `Argon2id(password, salt, params)`. Derived once per unlock.
- **DEK** = 256 random bits from the CSPRNG, generated once at vault creation.
  The DEK actually encrypts the vault body.
- The DEK is stored **wrapped** (AEAD-encrypted) under the KEK.

**Why the extra layer instead of encrypting the vault directly under the KEK?**

1. **Cheap password change.** Changing the master password re-runs Argon2id with
   a *new* salt to get a new KEK, then re-wraps the *same* DEK. The vault body is
   never re-encrypted from scratch under a password-derived key. Direct
   derivation would couple key rotation to data size.
2. **Cheap saves.** Argon2id (~0.5–1 s, tens of MiB) runs **once** at unlock.
   Every subsequent save re-encrypts the body under the already-in-memory DEK,
   which is fast. Direct derivation would tempt re-deriving on save (slow) or
   caching a password-derived key (same as this, without the clean rotation
   story).
3. **Clean separation of concerns:** the expensive, password-bound operation is
   isolated from the bulk-data operation.

The cost is one extra AEAD operation and ~60 stored bytes. Worth it.

---

## 2. Key derivation — Argon2id (`argon2-cffi`)

### Choice: Argon2id. Justified against alternatives.

| Candidate | Verdict | Reason |
|---|---|---|
| **Argon2id** | ✅ chosen | Winner of the Password Hashing Competition; RFC 9106. Memory-hard → defeats cheap GPU/ASIC parallelism that guts PBKDF2. The `id` variant is a hybrid: Argon2i-style (data-independent) first pass for side-channel resistance, Argon2d-style (data-dependent) later passes for GPU resistance. Recommended default. |
| PBKDF2 | ❌ | Available in `hashlib.pbkdf2_hmac` (stdlib) but **not memory-hard**. A modern GPU rig computes billions of PBKDF2-HMAC-SHA256/s. Only acceptable as a last-resort fallback; not our threat model's answer. |
| scrypt | ⚠️ acceptable | Memory-hard and battle-tested (`hashlib.scrypt` / `cryptography`), but Argon2 is newer, better analyzed for this exact use, and has cleaner parameterization. No reason to prefer it here. |
| bcrypt | ❌ | Not memory-hard; 72-byte input cap. A password *hashing* function, not a KDF for producing key material. Wrong tool. |
| Hand-rolled anything | ❌ | Never. |

**Library:** `argon2-cffi` — the maintained CFFI binding to the reference C
implementation of Argon2 (the same backend Django uses for its Argon2 password
hasher). We use the **low-level** API to derive *raw key bytes*, not the
high-level PHC-string hasher:

> `argon2.low_level.hash_secret_raw(secret, salt, time_cost, memory_cost,
> parallelism, hash_len, type=argon2.low_level.Type.ID)`

The high-level `PasswordHasher` is designed for *storing password verifiers*
(returns an encoded `$argon2id$...` string). We need raw bytes to use as a key,
so the low-level raw API is the correct one. Using the wrong one here is a
classic mistake.

### Parameters

We adopt **RFC 9106's second recommended option** as the default, tuned for
memory-constrained environments (a desktop is more constrained than a server and
must not fail on an 8 GiB laptop):

| Parameter (`argon2-cffi` name) | Default | Meaning |
|---|---|---|
| `memory_cost` | **65536 KiB (64 MiB)** | Memory cost. The lever that hurts GPU/ASIC attackers most. |
| `time_cost` | **3** | Iterations (passes over memory). |
| `parallelism` | **4** | Lanes. Matches RFC 9106; may be reduced to 1 on single-core targets. |
| `salt` | **16 bytes** random | See §4. |
| `hash_len` | **32 bytes** | 256-bit KEK for AES-256. |
| `type` | **Type.ID** | Argon2id. |

**Why these values, concretely:**

- **64 MiB, not 2 GiB.** RFC 9106's *first* option (2 GiB, t=1) targets backend
  servers that can spare the RAM. On a general desktop, allocating 2 GiB for an
  interactive unlock is hostile: it fails or thrashes on modest machines and slows
  the user. 64 MiB is the RFC's explicit low-memory recommendation and well above
  OWASP's floor (19 MiB). It still forces an attacker to commit 64 MiB *per
  parallel guess*, which is what breaks large-scale GPU attacks economically.
- **time_cost = 3.** With reduced memory you raise the time cost to compensate;
  RFC 9106 pairs 64 MiB with t=3 for this reason.
- **parallelism = 4.** Uses available cores to keep wall-clock latency low at a
  given total work. Lowered to 1 where determinism/portability matters more than
  latency.

**Calibration, not dogma.** These are *defaults baked into new vaults*. At vault
creation the tool may optionally calibrate `memory_cost`/`time_cost` to hit a
target unlock time (~0.5–1.0 s) on *that* machine and store the chosen values. The
parameters are recorded in the file header (§5) so a vault created on a strong
machine still opens on a weaker one, and so parameters can be raised later as
hardware improves (re-derivation on the next password change). **Parameters are
versioned data, never hard-coded constants at read time.**

**Security note on reading parameters back:** because the header is plaintext and
is needed *before* we can derive the key that authenticates the file, an attacker
can edit the parameters (Threat A4). We therefore validate them against hard
bounds *before allocating anything*:

- `memory_cost` within `[19456, 1048576]` KiB (19 MiB … 1 GiB),
  `time_cost` within `[1, 16]`, `parallelism` within `[1, 8]`.
- Out-of-range ⇒ reject the file immediately, before Argon2 runs.

Lowering parameters does not help an attacker (they still need the password); the
only exploitable direction is *raising* `memory_cost` to force a huge allocation
(DoS), so the upper bound is the load-bearing check.

---

## 3. Authenticated encryption of the vault

### Choice: AES-256-GCM (primary), via `cryptography`. XChaCha20-Poly1305 documented as the alternative.

We need an **AEAD** (authenticated encryption with associated data): one primitive
giving confidentiality *and* integrity, with the ability to bind plaintext header
fields. Encrypt-then-MAC hand-assembly is explicitly rejected — it is a classic
source of composition bugs.

| Candidate | Verdict | Reason |
|---|---|---|
| **AES-256-GCM** | ✅ primary | `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Backed by OpenSSL → hardware-accelerated (AES-NI) and constant-time on essentially all modern x86/ARM. Ubiquitous, heavily reviewed. `pyca/cryptography` is our single AEAD dependency. One sharp edge — the 96-bit nonce (§3.1) — which our design neutralizes. |
| ChaCha20-Poly1305 (IETF) | ⚠️ in-library alt | `...aead.ChaCha20Poly1305`, same library. Constant-time in pure software (no AES-NI needed), so preferable on hardware lacking AES acceleration. Shares the 96-bit nonce limit. A fine drop-in; we default to AES-GCM for hardware speed but the design is agnostic (selected via the `aead_id` header byte). |
| **XChaCha20-Poly1305** | ⚠️ strong alt, extra dep | 192-bit nonce ⇒ random nonces never collide in practice, removing nonce-management burden entirely. **Not exposed by `pyca/cryptography`** — only IETF ChaCha20-Poly1305 (96-bit) is. It requires **PyNaCl** (libsodium). We keep the dependency surface minimal, so this is the documented fallback, not the default. |
| AES-CBC + HMAC (manual EtM) | ❌ | Correct only if assembled perfectly (MAC covers IV + ciphertext, constant-time compare, no padding oracle). Every one of those is a footgun. Rejected in favor of a single AEAD call. |
| AES-GCM-SIV | ⚠️ ideal-but-absent | Nonce-*misuse-resistant* — theoretically the best fit — but not in `pyca/cryptography`. Not worth a fragile dependency when our nonce discipline (§3.1) already closes the gap. |

**Tag length: 128 bits (16 bytes), always.** No truncation. (Note: `AESGCM.encrypt`
returns `ciphertext || tag` as one blob and `AESGCM.decrypt` expects the same;
the tag is not a separate parameter. The file format §5 stores that blob as-is.)

### 3.1 Nonce / IV generation and the nonce-reuse hazard

This is the single most dangerous part of using GCM, so it is specified
explicitly.

**The hazard.** GCM (and any Poly1305/GHASH AEAD) is catastrophically broken if a
`(key, nonce)` pair is *ever* reused for two different plaintexts: an attacker can
recover the authentication subkey and forge messages, and can XOR the two
plaintexts. GCM's nonce is only 96 bits, so *random* nonces also carry a birthday
risk — collision probability approaches ~2⁻³² after ~2³² encryptions under one
key.

**Why it is a non-issue in our design:**

1. The vault is rewritten **whole** on each save — there is exactly **one**
   ciphertext body per file, not a stream of millions of messages. A human editing
   a password vault produces maybe thousands of saves in a lifetime, nowhere near
   2³².
2. Each save generates a **fresh 12-byte nonce from the CSPRNG** (`os.urandom(12)`).
   At even 2²⁰ (~1M) saves, collision probability under one DEK is ~2⁻⁵⁶ —
   negligible.
3. **Defense in depth:** the header carries a `save_counter`. We never write a body
   with a counter we have already used in this vault's lifetime, and if the counter
   ever approached the safety threshold we would rotate the DEK. In practice it
   never will.
4. There are only **two** distinct encryption contexts and they use **independent**
   nonces: (a) wrapping the DEK under the KEK — this changes only on password change
   — and (b) encrypting the vault body under the DEK. They are under different keys
   anyway, so cross-context collision is meaningless.

**Rules the code must follow (checklist):**
- Nonces come *only* from `os.urandom` (or `secrets.token_bytes`) — never a counter
  alone, never a timestamp, never the `random` module, never a UUID.
- A nonce is generated immediately before each encryption and stored next to its
  ciphertext.
- A given DEK never encrypts two bodies under the same nonce — guaranteed by fresh
  random generation + the counter guard.
- Nonces are **not secret** and are stored in the clear (they only need to be
  unique, not unpredictable).

> If we adopt the XChaCha20-Poly1305 alternative (PyNaCl), this section collapses
> to "generate a 24-byte random nonce per encryption" — the 192-bit space makes
> collision a non-concern with no counter bookkeeping. That is the sole reason it
> remains an attractive fallback.

### 3.2 Associated Data (AAD) — binding the header

The AEAD's associated-data input authenticates data transmitted in the clear but
which must not be altered. **We pass header bytes as AAD** so the (unencrypted)
header cannot be tampered with undetected:

- **DEK-wrap AAD** = the *KDF header* (magic, version, kdf_id, aead_id, Argon2
  params, salt). Everything that defines the KEK derivation and the algorithms.
  It deliberately excludes `save_counter`, so the wrapped-DEK block does not have
  to change on every save (only on password change).
- **Body AAD** = the *full header* (the KDF header **plus** `save_counter`). So the
  counter — and every other header field — is authenticated by at least one tag.

Consequences:
- Tampering with the salt or KDF parameters (Threat A4) makes tag verification fail
  — the file is rejected rather than silently mis-decrypting.
- Prevents a *downgrade/confusion* attack where an attacker swaps header fields
  (e.g. the `aead_id`) to steer decryption.
- Note this does not stop the *pre-authentication* DoS of A4 (params are consumed
  before the tag can be checked), which is why §2's range check still runs first.

---

## 4. Salt generation and storage

- **16 bytes (128 bits)** from `os.urandom` — the CSPRNG, never the `random`
  module.
- **Unique per vault**, generated once at creation, and **regenerated on every
  master-password change** (a new KEK derivation gets a fresh salt).
- Stored **in plaintext** in the file header. A salt is *not* secret; its job is to
  (a) defeat precomputation/rainbow tables and (b) ensure two users with the same
  password get different KEKs. 128 bits makes global salt collision irrelevant.
- The salt is covered by the AEAD tag via AAD (§3.2): not confidential, but not
  tamperable undetected.

---

## 5. Vault file format

A single binary file. Layout (conceptual — exact serialization pinned in Stage 2,
but *all multi-byte integers little-endian, all lengths explicit, no ambiguity*):

```
┌─────────────────────────── PLAINTEXT HEADER ─────────────────────────────────────┐
│ magic            b"SVLT"       4 bytes   — file-type sniff / fail fast            │
│ format_version   uint16                  — reject unknown versions                │
│ kdf_id           uint8                   — 1 = Argon2id                           │
│ aead_id          uint8                   — 1 = AES-256-GCM, 2 = XChaCha20-Poly1305 │
│ argon2_m         uint32  (KiB)                                                    │
│ argon2_t         uint32                                                           │
│ argon2_p         uint32                                                           │
│ salt             16 bytes                                                         │
│   └─ bytes[0:36] = KDF header  → AAD for the DEK wrap                             │
│ save_counter     uint64                  — monotonic, defense-in-depth (§3.1)     │
│   └─ bytes[0:44] = full header → AAD for the body                                │
├─────────────────────────── WRAPPED DEK ──────────────────────────────────────────┤
│ dek_nonce        12 bytes (24 if XChaCha20)                                       │
│ dek_blob         48 bytes                — 32-byte DEK ciphertext ‖ 16-byte tag   │
├─────────────────────────── ENCRYPTED BODY ───────────────────────────────────────┤
│ body_nonce       12 bytes (24 if XChaCha20)                                       │
│ body_len         uint32                  — length of body_blob                    │
│ body_blob        body_len bytes          — vault-JSON ciphertext ‖ 16-byte tag    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

**What is plaintext:** magic, version, algorithm ids, KDF parameters, salt,
save_counter, and the nonces. None of these are secret; all except the nonces are
authenticated as AAD (nonces are inherently bound into their own AEAD operation).

**What is encrypted:** the DEK (under the KEK) and the *entire* vault content under
the DEK — including entry **titles, usernames, URLs, and notes**, not just
passwords. Metadata is a protected asset (THREAT_MODEL §1); we do not leak which
sites a user has accounts on.

**Serialized plaintext is JSON**, not `pickle`/`marshal`/`yaml`. Deserializing
untrusted data with `pickle`/`yaml.load`/`eval` is arbitrary code execution in
Python; even though our plaintext is authenticated before parsing, we use a
data-only format (`json`) so a serialization bug can never become code execution.

**How integrity is verified:** two AEAD tags. (1) The DEK-wrap tag: a wrong KEK
(wrong password) or a tampered wrapped-DEK/KDF-header fails here. (2) The body tag:
any modification of the body ciphertext, its nonce, or the full header (via AAD)
fails here. Verification happens *before* any plaintext is released:
`AESGCM.decrypt` checks the tag and raises `InvalidTag` before returning bytes; we
never parse unverified plaintext.

**Serialization discipline:** fixed, explicit, length-prefixed encoding. No
attacker-controlled length is trusted without bounds-checking against the actual
file size. Reject the file on any structural inconsistency (short read, impossible
length, unknown id) *before* cryptographic work where possible.

---

## 6. Libraries — vetted, and where naïveté bites

**We implement zero primitives.** Concretely:

| Need | Choice | Notes |
|---|---|---|
| Argon2id | **`argon2-cffi`** (`low_level.hash_secret_raw`, `Type.ID`) | CFFI binding to the reference C Argon2. Use the *raw* API for key bytes, not the PHC-string hasher. |
| AEAD (AES-256-GCM) | **`cryptography`** (`...aead.AESGCM`) | OpenSSL-backed, AES-NI, heavily reviewed. `ChaCha20Poly1305` from the same package is the software-constant-time alternative. |
| CSPRNG | **`os.urandom`** / **`secrets`** | The only acceptable randomness source for salts, nonces, DEK. **Never** the `random` module. |
| Constant-time compare | **`hmac.compare_digest`** (stdlib) | For any explicit tag/secret comparison we do ourselves (prefer letting the AEAD verify). |
| Serialization | **`json`** (stdlib) | Data-only. Never `pickle`/`marshal`/`yaml.load`/`eval` on vault data. |
| Best-effort zeroing | **`ctypes.memset`** over `bytearray` | See §7 and THREAT_MODEL §6 for the honest limits. |

Dependency policy: pin **exact versions with hashes** (`pip` hash-checking mode /
a locked `requirements.txt`), review the transitive tree, and prefer the smallest
number of well-maintained crypto libraries. Both `argon2-cffi` and `cryptography`
ship compiled components (CFFI / a Rust+OpenSSL core) — vetted, but native code is
supply-chain surface (THREAT_MODEL N6). Two crypto dependencies is the whole list.

**Places where a naïve implementation introduces a real vulnerability** — flagged
now so review catches them in Stage 2:

1. **`pickle`/`yaml.load`/`eval` on vault data** → arbitrary code execution. → *JSON
   only.*
2. **`random` / `uuid` for salt or nonce** → predictable, non-uniform crypto
   material. → *`os.urandom` / `secrets` only.*
3. **Reusing a `(key, nonce)`** → total GCM break. → *Fresh CSPRNG nonce per
   encryption; never a counter/timestamp as the nonce (§3.1).*
4. **Rolling your own Encrypt-then-MAC / CBC+HMAC** → padding oracles, MAC-coverage
   gaps, non-constant-time compares. → *Use a single AEAD call.*
5. **Non-constant-time tag/secret comparison** (`==` on bytes) → timing oracle. →
   *`hmac.compare_digest`; better, let the AEAD verify the tag.*
6. **Using `argon2-cffi`'s high-level `PasswordHasher`** (PHC verifier strings)
   where raw key bytes are needed → wrong primitive. → *`hash_secret_raw`.*
7. **PBKDF2 with a low iteration count** because it's in `hashlib` → weak against
   GPUs. → *Argon2id with the §2 parameters.*
8. **Parsing plaintext before the tag is verified** → integrity bypass. → *Let
   `AESGCM.decrypt` verify first; only then `json.loads`.*
9. **Trusting header-declared lengths / parameters unchecked** → allocation DoS,
   out-of-bounds reads. → *Bounds-check every length against file size and every
   KDF parameter against the §2 limits before use.*

---

## 7. Key material in memory, and clearing it

See **THREAT_MODEL §6** for the full honest treatment; summarized here as design
requirements.

**What we do (best-effort):**
- Keep the KEK, DEK, and decrypted plaintext confined to as few, as short-lived
  references as possible; `del` them promptly so the GC can reclaim.
- Prefer `bytearray` for buffers we fully own and overwrite them with
  `ctypes.memset(...)` when done.
- Read the master password with `getpass.getpass()` (no echo), use it, and drop the
  reference immediately.
- Keep the unlocked window short; an auto-lock timeout drops the DEK and plaintext.
- Where the OS allows, disable core dumps (`resource.setrlimit(RLIMIT_CORE,(0,0))`)
  and optionally `mlock` the process memory — defense-in-depth, not guarantees.

**Honest limits (do not overclaim):** CPython cannot truly wipe secrets. `bytes`
and `str` are immutable and un-overwritable; `getpass` yields an immutable `str`;
`argon2-cffi`/`cryptography` hold keys as `bytes` and make internal copies we
cannot reach; the interpreter may page memory to swap or a core dump. Memory
hygiene here **shrinks the exposure window; it does not eliminate it.** Anyone in
THREAT_MODEL N1–N3 defeats it.

---

## 8. Concrete failure modes the code MUST handle

Each is a testable requirement for Stage 2.

1. **Tampered/corrupted vault fails loudly.** Any AEAD tag mismatch (`InvalidTag`,
   body or DEK-wrap) ⇒ hard abort with a generic error, no partial data, non-zero
   exit. Never "recover what we can."
2. **Wrong password is indistinguishable from tampering.** Both surface as one
   generic authentication error; both pay full Argon2id cost; no message reveals
   which, and none reveals "close" guesses (A6).
3. **No plaintext ever touches disk.** Saves serialize → encrypt → write
   *ciphertext* to a temp file in the same directory → `flush` + `os.fsync` →
   `os.replace` (atomic) over the vault → fsync the directory. A crash leaves either
   the old vault or the new one, never a torn or plaintext file. No plaintext temp.
4. **Unknown version / algorithm id ⇒ refuse.** Never guess; never silently
   downgrade. Forward-compat is via explicit version handling only.
5. **Out-of-range KDF parameters ⇒ refuse before allocating** (A4, §2).
6. **Structural malformation ⇒ refuse before crypto.** Short file, impossible
   length prefixes, bad magic ⇒ reject with bounds-checked parsing; never trust a
   length against a smaller actual file.
7. **CSPRNG is the only randomness.** `os.urandom`/`secrets` exclusively; the
   `random` module never appears in the crypto path.
8. **First-run / empty-vault path is not special-cased into weakness.** A new vault
   gets a fresh salt, fresh DEK, real parameters — the same code path, no "empty
   means skip encryption."
9. **Master-password change is atomic and does not weaken the DEK.** New salt → new
   KEK → re-wrap the *same* DEK → atomic replace. A failure mid-change leaves the
   old vault fully intact.
10. **Plaintext is only parsed after authentication**, and always with `json`
    (never `pickle`/`eval`).
11. **Concurrent access is refused, not raced.** Detect a second instance (an
    advisory lock / exclusive open) so two writers cannot interleave and corrupt
    the vault.

---

## 9. Open questions deferred to later stages (flagged, not hidden)

- Clipboard/terminal output minimization and clipboard auto-clear (THREAT_MODEL
  N5) — output path, Stage ≥3.
- Auto-lock timeout tuning.
- Whether to offer parameter *upgrade-on-open* (re-wrap DEK with stronger params
  when opening an old vault).
- Backup guidance / documentation (rollback & availability are user-side, N7).

None of these change the core cryptographic design above; they are handled on top
of it.
