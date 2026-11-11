# Architecture

Vault follows a **Hexagonal (Ports & Adapters)** architecture. The domain and application logic are entirely isolated from I/O — storage and cryptography are injected as trait objects, making every adapter independently replaceable and testable.

---

## Module Map

```
src/
├── main.rs                   # Entry point: hardens the process, wires adapters → engine → CLI
│
├── domain/                   # Pure business rules, no I/O, no deps
│   ├── mod.rs
│   ├── models.rs             # Entry, KdfParams, VaultState
│   ├── format.rs             # the vault file format, byte by byte
│   ├── generator.rs          # generated passwords and passphrases (EFF word list)
│   ├── health.rs             # health report: reused, short and oldest passwords
│   ├── ports.rs              # CryptoPort, StoragePort (traits)
│   └── errors.rs             # VaultError, CryptoError, StorageError
│
├── application/
│   ├── mod.rs
│   └── engine.rs             # VaultEngine — orchestrates all operations
│
└── adapters/
    ├── mod.rs
    ├── aes_crypto.rs         # CryptoPort impl: AES-256-GCM + Argon2id
    ├── file_storage.rs       # StoragePort impl: ~/.vault/ filesystem
    ├── process.rs            # no core dumps, no same-user debugging
    └── cli/
        ├── mod.rs            # VaultCli — REPL loop, command dispatch
        ├── clipboard.rs      # copies out of clipboard history, cleared after 30 s
        ├── commands.rs       # Command enum; lines split into words like a shell
        ├── input.rs          # the main prompt, on its own thread (auto-lock)
        └── ui.rs             # VaultHelper (tab-completion, colors)
```

---

## Layer Responsibilities

### `domain/`

The innermost layer. Contains only:

- **`models.rs`** — Plain data structures:
  - `Entry` — a single credential (`service`, `username`, `passwd`, `notes`, `history`, `created_at`, `updated_at`). Derives `Zeroize` and `ZeroizeOnDrop`, so it is wiped whenever it is dropped, and its `Debug` output leaves the secrets out.
  - `OldPassword` — a previous password and when it was replaced. `Entry::update` puts the replaced password at the front of `history`, which keeps at most `HISTORY_LEN` (10).
  - `KdfParams` — Argon2id cost (memory, passes, lanes): `DEFAULT` for new keys, `LEGACY` for version-0 files.
  - `VaultState` — what the engine keeps about the open vault's key: its `salt` and `KdfParams`.
- **`format.rs`** — The file format as pure functions: `VaultFile::decode` (v0 to v3) and `encode` (v3), the header used as AES-GCM associated data, and the plaintext codec for the entries. No serialization library: every length is checked against the bytes present.
- **`ports.rs`** — Pure trait definitions:
  - `CryptoPort` — `salt_gen`, `init`, `reset`, `encrypt`, `decrypt`, `verify_password`, `random_below` (the randomness behind `domain::generator`)
  - `StoragePort` — `exists`, `set_path`, `get_path`, `load`, `save`, `load_backup`, `list_vaults`
- **`errors.rs`** — Typed error hierarchy:
  - `VaultError` — top-level (wraps `CryptoError` and `StorageError`)
  - `CryptoError` — adapter-level crypto failures
  - `StorageError` — adapter-level I/O failures

No I/O. External crates: only `zeroize`, `thiserror` and `chrono`.

---

### `application/`

The orchestration layer. `VaultEngine<S, C>` is generic over any `StoragePort` and `CryptoPort` implementation.

```
VaultEngine<S: StoragePort, C: CryptoPort>
├── storage: S
├── crypto: C
├── vault_state: Option<VaultState>   // None = locked
├── entries: BTreeMap<String, Entry>  // in-memory decrypted entries
├── dirty: bool                       // true = uncommitted changes
└── kdf: KdfParams                    // cost for new keys (DEFAULT; cheap in unit tests)
```

#### Operations

| Method | Description |
|--------|-------------|
| `create_vault(name, pw)` | Checks the name and the password's length, generates salt, derives key, commits empty state to disk |
| `unlock(name, pw)` | Loads file, derives key, decrypts entries into memory; rewrites an old-format or cheaper-keyed file at once and reports it as `Upgrade` |
| `lock()` | Drops the entries (which wipes them), clears vault state, resets the key |
| `lock_if_clean()` | `lock()`, unless there are uncommitted changes (auto-lock); returns whether it locked |
| `commit()` | Encrypts current entries, saves to disk with fresh nonce; they become the new last commit |
| `changes()` | What differs from the last commit: entries added, removed, renamed, or changed (which fields). `is_dirty()` is whether there are any, so edits that undo each other leave the vault clean |
| `discard()` | Goes back to the last commit, keeping the vault open |
| `health()` | Reused and short (under 12 characters) passwords, and when each was set; the report holds names and dates, never passwords |
| `restore_backup(pw)` | Loads the backup in place of the open entries, as uncommitted changes. Checks the password, and derives the backup's own key when it differs (an upgrade's backup is the old file), going back to the vault's key afterwards |
| `add(svc, user, pw)` | Inserts a new `Entry`, marks dirty |
| `delete(svc)` | Removes entry (marks dirty only on success) |
| `rename_entry(old, new)` | Renames an entry, keeping its password, notes, history and creation date |
| `get(svc)` | Returns a reference to an entry |
| `get_entries()` | Returns sorted list of service names |
| `get_vaults()` | Delegates to `StoragePort::list_vaults` |

---

### `adapters/aes_crypto.rs`

Implements `CryptoPort` using:

- **Argon2id** for key derivation from password + salt, at the vault's `KdfParams`, in working memory the adapter allocates and wipes afterwards
- **`Aes256Gcm`** from the `aes-gcm` crate for AEAD encryption, with the file header as associated data
- A fresh **random nonce** (via `OsRng`) on every `encrypt` call
- `ZeroizeOnDrop` on the struct — the key is wiped when it is dropped
- `reset()` — wipes the key in place without dropping the struct (on `lock` and after a failed unlock)

---

### `adapters/file_storage.rs`

Implements `StoragePort` using the local filesystem under `~/.vault/`.

#### Write Protocol (atomic, safe across sessions)

```
1. Ensure ~/.vault/ exists and take ~/.vault/.lock (flock): commits from
   every session run one at a time
2. Read the current <name>.vault; if its SHA-256 differs from the version this
   session last loaded or saved, abort with StorageError::Conflict
   (another session saved in the meantime; nothing is written)
3. Write the current version to <name>.bkp, atomically (see below)
4. Write the new content to <name>.vault, atomically
5. Remember the new content's SHA-256; release the lock

Atomic write: write <file>.tmp (mode 0600) → fsync it → rename it over <file>
→ fsync the directory. A crash leaves either the old file or the new one.
```

Several sessions can have the same vault open; only a stale commit is refused.

#### `get_path()` — returns the vault **stem** (e.g. `"personal"`), not the full filesystem path, so the prompt displays cleanly.

---

### `adapters/cli/`

The outermost layer. Implements the interactive REPL.

- **`VaultCli<S, C>`** wraps the engine and a `rustyline::Editor` for line editing.
- **`run()`** — main loop: refreshes the completion names → reads input → parses command (`Command::parse`) → dispatches to `handle_command`.
- **Auto-lock** — the main prompt is read on its own thread (`input.rs`), so the main thread, which owns the engine, can wait for the line with a timeout. When `VAULT_AUTO_LOCK` (300 s by default) passes at the prompt, it calls `lock_if_clean()`: the vault locks, or, with uncommitted changes, stays open with a one-time warning. Everything else that reads the terminal runs on the main thread while the prompt thread waits for its next request. The notice is written directly (rustyline's external printer stalls on input arriving in bursts in 17.0.2).
- **`confirm_exit()` / `confirm_lock()`** — when `dirty = true`, prompts the user to commit/discard before proceeding.
- **`commands::words`** — splits a line as a shell does: quotes keep spaces in a word, and `\` escapes outside single quotes (which is also how rustyline's file completion writes spaces). `Command::parse` works on these words, so names and paths can have spaces.
- **`VaultHelper`** — implements `rustyline::Completer`. Only the word under the cursor is replaced, split the same way as the parser splits it (quotes included), and names that need quotes are offered in them, and what is offered depends on its position: command names in the first word; in the first argument, entry names (`get`, `copy`, `update`, `rm`), vault names (`unlock`, `drop`) or file paths (`import`, `export`), as declared by `Command::first_argument`. The CLI hands it the current entry and vault names before each prompt.
- **`find()`** — the interactive selector: a `dialoguer` `FuzzySelect` over the entry names, then a `Select` with the actions (copy password or username, show, update, remove), which reuse the regular commands. Esc and Ctrl-C cancel.
- **`SecretClipboard`** (`clipboard.rs`) — what `copy` uses. Each copy is marked as a secret for clipboard managers and gets a timer that clears it 30 s later, if the clipboard still holds it (compared by SHA-256) and no newer copy was made. Dropping it, when the program exits, clears a copy still pending. The system clipboard sits behind a small `Backend` trait, so tests use a fake.
- Passwords are read with `rpassword` (no echo).
- Other answers (`update`'s username, y/N confirmations, the commit menus) go through a second `rustyline` editor: arrows and Ctrl-U work, Ctrl-C cancels, and neither Tab completion nor history leak in from the main prompt.

---

## Data Flow: `commit`

```
entries: BTreeMap<String, Entry>
    │
    ▼ format::encode_entries()        (one allocation, zeroized after use)
plaintext: Vec<u8>
    │
    ▼ CryptoPort::encrypt(plaintext, header)   header = format::header(v1, kdf, salt)
(cipher: Vec<u8>, nonce: [u8; 12])
    │
    ▼ VaultFile { version: 1, kdf, salt, nonce, cipher }.encode()
file bytes: header | nonce | cipher
    │
    ▼ StoragePort::save()  (conflict check, backup, atomic replace)
~/.vault/<name>.vault
```

## Data Flow: `unlock`

```
~/.vault/<name>.vault
    │
    ▼ StoragePort::load()
file bytes
    │
    ▼ VaultFile::decode()             (v0 or v1; bounded costs; newer → refused)
VaultFile { version, kdf, salt, nonce, cipher }
    │
    ├──► CryptoPort::init(password, salt, kdf)   → derives AES key
    │
    ▼ CryptoPort::decrypt(cipher, nonce, associated_data)   (header for v1, none for v0)
plaintext: Vec<u8>
    │
    ▼ format::decode_entries()        (then the plaintext is zeroized)
entries: BTreeMap<String, Entry>
    │
    └──► if v0 or kdf weaker than the engine's: new salt, key at the current
         cost, commit → Upgrade::Done (old file kept as .bkp)
```
