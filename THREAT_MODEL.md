# Threat Model — Secure Vault

**Status:** Stage 1 (design). No implementation exists yet.
**Scope:** A local, offline, single-user password manager. A Python CLI application
that stores credentials in a single encrypted vault file on the local disk. No
network, no cloud, no sync, no browser integration.

This document states, as precisely as it can, *what the tool defends and what it
does not*. A narrow, honest scope is the point. An overclaimed guarantee that
fails silently is worse than an absent one, because users make real decisions
based on it.

---

## 1. System model

- One user, one machine, one master password.
- The vault is a single file (`vault.dat`) on local storage.
- The application runs on demand: it starts, the user authenticates with the
  master password, it decrypts the vault into memory, the user reads or edits
  entries, it re-encrypts and writes the file, it exits.
- No secret material is intended to persist unencrypted anywhere — not on disk,
  not in a config file, not in an environment variable, not in shell history.
- The vault file is assumed to be *copyable by an adversary*. Designing as if the
  attacker already has the file is the core assumption; everything else follows.

### Assets (in priority order)

| Asset | Why it matters |
|---|---|
| Stored credentials (site passwords, notes) | The whole point. Disclosure is the worst outcome. |
| Master password | Root of trust. Compromise = total compromise. |
| Derived key material (KEK/DEK) held in memory while unlocked | A live copy of the keys to everything. |
| Vault metadata (entry titles, usernames, URLs, timestamps) | Not the password itself, but sensitive — reveals *which* accounts exist. Treated as a protected asset and encrypted, not left in plaintext. |
| Integrity of the vault | A silently altered vault could feed the user a wrong/attacker-chosen credential. |

### Trust boundaries

```
  ┌──────────────────────────────────────────────────────────┐
  │  User's running OS session + Python runtime (TRUSTED)     │
  │                                                           │
  │   master password (from keyboard, via getpass)            │
  │        │                                                  │
  │        ▼                                                  │
  │   ┌─────────────────────┐      derive/encrypt/decrypt     │
  │   │  Secure Vault (CLI) │◄──── in process memory          │
  │   └─────────┬───────────┘                                 │
  │             │ read/write ciphertext only                  │
  └─────────────┼────────────────────────────────────────────┘
                ▼
        ┌───────────────┐   ← TRUST BOUNDARY: everything below is
        │  vault.dat    │     assumed to be in adversary hands
        │  (on disk)    │
        └───────────────┘
```

The **primary trust boundary is the disk**. Data crossing it (the vault file)
must be useless without the master password. Inside the process, while unlocked,
we hold plaintext and keys — that memory is *inside* the trust boundary and is
only as safe as the OS session and the Python runtime (see non-goals, and §6 on
why Python makes this boundary especially porous).

---

## 2. Attacker capabilities we DO defend against

**A1 — Offline attacker in possession of the vault file.**
Lost/stolen laptop, stolen backup, a copied file from a shared or synced folder,
a discarded drive, a cloud-backup provider that has the file. The attacker has
the ciphertext, unlimited time, and can run offline password guessing on GPUs or
ASICs.

- *Defense:* Content is encrypted under a key derived from the master password
  via a **memory-hard KDF (Argon2id)**, making each guess expensive in both time
  and memory, degrading GPU/ASIC parallelism. AEAD (AES-256-GCM) provides
  confidentiality and integrity. The security ceiling is `Argon2id cost ×
  master-password entropy` — see the honesty note in §4.

**A2 — Disk theft / cold storage / forensic recovery.**
Same as A1 but includes recovering *deleted* copies, filesystem journals, and
old versions.

- *Defense:* No plaintext is ever written to disk (§ failure modes in DESIGN.md).
  Writes go through an encrypted temp file + atomic replace so a crash never
  leaves a half-written or plaintext artifact. We cannot guarantee the
  *filesystem* or *SSD wear-leveling* didn't retain an old encrypted block — but
  every retained block is still ciphertext, so recovery yields nothing new.

**A3 — Vault tampering / bit-flipping / rollback of content.**
An attacker who can write to the file tries to corrupt it, flip bits to change a
stored value, splice in ciphertext from elsewhere, or truncate it.

- *Defense:* Authenticated encryption. Any modification — including to the
  plaintext header fields, which are bound as Associated Data — causes tag
  verification to fail and the load to **abort loudly**. There is no "best
  effort" partial decrypt. (Rollback to a *previous whole valid vault the user
  themselves produced* is out of scope for a single-file offline tool — see N7.)

**A4 — KDF parameter tampering for denial of service.**
The KDF parameters live in the plaintext header and must be read *before* the key
that authenticates the file can be derived. An attacker edits them to demand,
say, 64 GiB of memory.

- *Defense:* Parameters are range-checked against hard upper bounds on load;
  out-of-range headers are rejected before any allocation. (Lowering the
  parameters does not help the attacker — they still lack the password — but
  raising them is a DoS, so only the upper bound needs enforcing. Detailed in
  DESIGN.md.)

**A5 — Weak-password *offense* by the tool itself.**
A footgun where the tool accepts a trivially weak master password and implies it
is safe.

- *Defense:* An entropy estimate is shown at master-password creation and very
  weak passwords are warned against. We *cannot* prevent a determined user from
  choosing a weak password; we can refuse to pretend it is strong.

**A6 — Information leak on failed unlock.**
An attacker (or shoulder-surfer of error messages) tries to learn something from
how a wrong password fails.

- *Defense:* "Wrong password" and "corrupted/tampered vault" are
  indistinguishable to the caller: both surface as a single generic
  authentication-failed error, both pay the full Argon2id cost. No oracle that
  says "the password was close" or "the file is fine but the password is wrong."

---

## 3. Explicit NON-GOALS — what this tool does NOT protect against

These are stated bluntly. If any of the following is in your threat model, this
tool is **not** sufficient, and no combination of its settings will make it so.

**N1 — A compromised operating system.**
Rootkit, malicious kernel, evil admin, backdoored Python interpreter or C
extension. If the platform executing our code is hostile, it can read our memory,
log our syscalls, and replace our binary. We run *on top of* the OS and the
CPython runtime and trust them completely. Nothing we do survives an OS-level
compromise.

**N2 — Malware / keyloggers on the running machine.**
A keylogger captures the master password as it is typed. Infostealer malware
reads process memory while the vault is unlocked or scrapes the decrypted vault.
This is out of scope. A local password manager cannot defeat code running with
your privileges on your own account.

**N3 — Live memory scraping while unlocked (Python makes this WORSE — read §6).**
While the vault is open, plaintext credentials and the derived keys are in RAM.
Another process with debug/ptrace rights (or root) can read them. In CPython we
**cannot** reliably erase this material even after use — immutable `bytes`/`str`
objects cannot be overwritten, the interpreter copies them freely, and secrets
may be paged to swap, captured in a hibernation image, or written to a core dump.
We minimize the *window* and disable core dumps where the OS allows, but we make
**no** claim that secrets are ever truly gone from memory. This is a hard limit
of the language and platform; it is documented in §6, not hidden.

**N4 — Coerced disclosure ("rubber-hose") and shoulder-surfing.**
If someone compels you to reveal the master password, or watches you type it, the
cryptography is irrelevant. No plausible-deniability / hidden-volume feature is
offered; if it were, it would be advertised honestly as such, and it is not in
scope.

**N5 — Output-path leakage after decryption.**
Once a password is *shown* in the terminal or *copied to the clipboard*, it has
left the vault's protection: terminal scrollback, shell history, tmux/screen
buffers, and the OS clipboard (readable by any app, often synced across devices)
are all plaintext channels. The tool minimizes this — the master password and
entry passwords are never echoed, no secret is accepted as a command-line
argument, and `get` masks the password unless `--show` is passed — but it
**cannot** control what the OS or other applications do with output. Treat
displayed/copied secrets as exposed.

**N5.1 — The clipboard, specifically (the `copy` command).**
The `copy` command trades one exposure for a smaller, time-boxed one: instead of
printing the password to a terminal that keeps scrollback, it puts it on the
system clipboard and clears it after a timeout. Being precise about what this
does and does not buy:

*What it mitigates:*
- **Shoulder-surfing and terminal scrollback** — the password is never rendered
  to the screen at all.
- **Leftover clipboard contents** — the password does not sit on the clipboard
  indefinitely; it is removed after the timeout (default 20 s), on Ctrl-C, or on
  `SIGTERM`.
- **Clobbering the user's own clipboard** — the clear is skipped if the user
  copied something else in the meantime, so it only ever removes its own value.

*What it does NOT mitigate:*
- **Other processes reading the clipboard during the window.** On essentially
  every OS the clipboard is readable by any process running as the same user. A
  malicious or curious process (the N2 out-of-scope set) can read the password at
  any point before it is cleared. Auto-clear shortens this window; it does not
  eliminate it.
- **Clipboard-manager history.** Many desktops and clipboard-manager tools record
  a *history* of clipboard entries. Our clear overwrites the *current* clipboard
  but cannot reach into a manager's history database — a copied password may
  persist there after we have cleared the live clipboard. Users with such tools
  should exclude this tool or disable history.
- **Clipboard sync across devices.** Some OSes mirror the clipboard to other
  signed-in devices; the password may reach those before the clear, and our clear
  does not necessarily propagate.
- **Non-graceful termination.** If the process is `SIGKILL`ed, the machine loses
  power, or it crashes, the clear never runs and the password remains on the
  clipboard until something overwrites it.

In short: `copy` is a convenience that reduces the *screen* and *dwell-time*
exposure of N5, not a defense against a hostile process on the machine (that
remains N2, out of scope).

**N6 — Supply-chain compromise of the toolchain or dependencies.**
A backdoored PyPI package, a typosquatted dependency, a compromised build of
`cryptography`/`argon2-cffi`, or a tampered Python interpreter can defeat
everything. We reduce this surface (minimal, vetted, version-and-hash-pinned
dependencies; no hand-rolled crypto) but do not claim to eliminate it. See
DESIGN.md §libraries.

**N7 — Rollback / replay of whole prior vaults; availability.**
An attacker who repeatedly replaces the file with an *older, legitimately-produced
version the user once saved* can revert a password change. Detecting this
requires trusted external state (a monotonic counter kept somewhere the attacker
can't roll back), which a single offline file cannot provide. Likewise,
availability is not protected: an attacker who can write the file can simply
delete it. Mitigation is user-side backups, not cryptography.

**N8 — Side channels beyond our layer.**
Cache-timing / power / EM analysis of the underlying AES or Argon2
implementations. We rely on the vetted primitives to be constant-time where it
matters and do not add our own timing-sensitive comparisons (we use
`hmac.compare_digest` for any secret comparison we perform ourselves). We do not
claim resistance to physical side-channel attacks on the host.

**N9 — Protecting a weak master password against A1.**
Restating for emphasis because it is the most common misunderstanding: Argon2id
raises the *cost per guess*, it does not make a guessable password unguessable. A
password in any wordlist or breach corpus will fall to an offline attacker
regardless of KDF settings.

---

## 4. The one honest sentence

> If an attacker steals only the vault file and your master password is strong and
> unique, your credentials are safe. If the attacker has code running on your
> unlocked machine, or your master password is weak, this tool cannot save you.

Everything in DESIGN.md exists to make the first half true and to avoid quietly
undermining it.

---

## 5. Summary table

| # | Threat | In scope? | Primary control |
|---|---|:--:|---|
| A1 | Offline attack on stolen vault | ✅ | Argon2id + AES-256-GCM |
| A2 | Disk theft / forensic recovery | ✅ | No plaintext on disk; atomic encrypted writes |
| A3 | Tampering / bit-flip / splice | ✅ | AEAD tag over content + header-as-AAD |
| A4 | KDF-param DoS via header edit | ✅ | Upper-bound validation before allocation |
| A5 | Tool accepting a weak password silently | ✅ | Entropy estimate + warning at creation |
| A6 | Info leak on failed unlock | ✅ | Generic failure, constant KDF cost |
| N1 | Compromised OS / runtime | ❌ | Out of scope (trusted base) |
| N2 | Keylogger / malware | ❌ | Out of scope |
| N3 | Live memory scraping / swap / core dump | ❌ | Best-effort only; Python cannot wipe memory (§6) |
| N4 | Coercion / shoulder-surfing | ❌ | Out of scope |
| N5 | Clipboard / terminal leakage of output | ⚠️ | Minimized (no echo, masked, clipboard auto-clear); not guaranteed — see N5.1 |
| N6 | Supply-chain compromise | ⚠️ | Reduced (pinned + hashed deps), not eliminated |
| N7 | Whole-vault rollback / deletion | ❌ | User backups |
| N8 | Physical / micro-architectural side channels | ❌ | Rely on vetted primitives |
| N9 | Weak master password vs offline attack | ❌ | Cannot be fixed by crypto |

---

## 6. Memory hygiene in Python — the honest limits (expands N3)

This section exists because Python's memory model materially weakens the
in-process protections a lower-level implementation could offer, and pretending
otherwise would be exactly the overclaiming this document is meant to avoid.

**What CPython prevents us from doing:**
- `bytes` and `str` are **immutable**. A secret stored in one **cannot be
  overwritten in place** — the memory is released only when the object is garbage
  collected, on the interpreter's schedule, and may be reused or paged out before
  then.
- `getpass.getpass()` returns the master password as an immutable `str`. From the
  instant it exists, we **cannot** erase it.
- `argon2-cffi` accepts the password as `bytes` and returns the derived key as
  `bytes`; `cryptography`'s AEAD takes the key as `bytes`. The KEK and DEK
  therefore *necessarily* exist as immutable `bytes` we cannot wipe, and the
  libraries may make internal C-level copies we cannot reach at all.
- The interpreter freely copies objects (slicing, encoding, buffer protocol),
  each copy an extra residue we do not control.

**What we still do (best-effort, honestly labeled as such):**
- Prefer `bytearray` for buffers we fully own, and overwrite them with
  `ctypes.memset` when done — knowing this covers only the copies we hold, not
  those inside the C libraries or the interpreter.
- Keep the unlocked window as short as the workflow allows; drop references
  (`del`) promptly so the GC *can* reclaim.
- Where the OS permits, disable core dumps for the process
  (`resource.setrlimit(RLIMIT_CORE, (0, 0))`) so a crash cannot spill secrets to
  disk, and optionally attempt to lock memory against swap (`mlock`/`mlockall`)
  — neither is guaranteed cross-platform, both are defense-in-depth, not a
  guarantee.

**The bottom line:** in Python, secrets in memory are best-effort minimized and
**never guaranteed erased**. Anyone in the N1–N3 out-of-scope set defeats these
measures. We state this plainly rather than imply RAM secrets are safe.
