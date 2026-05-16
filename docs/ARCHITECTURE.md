# Architecture

Vault follows a **Hexagonal (Ports & Adapters)** architecture. The domain and application logic are entirely isolated from I/O — storage and cryptography are injected as trait objects, making every adapter independently replaceable and testable.

---

## Module Map

```
src/
├── main.rs                   # Entry point: wires adapters → engine → CLI
│
├── domain/                   # Pure business rules, no I/O, no deps
│   ├── mod.rs
│   ├── models.rs             # Entry, VaultState
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
    └── cli/
        ├── mod.rs            # VaultCli — REPL loop, command dispatch
        ├── commands.rs       # Command enum
        └── ui.rs             # VaultHelper (tab-completion, colors)
```

---

## Layer Responsibilities

### `domain/`

The innermost layer. Contains only:

- **`models.rs`** — Plain data structures:
  - `Entry` — a single credential (`service`, `username`, `passwd`, `created_at`, `updated_at`). Derives `Zeroize` so it can be wiped from memory on lock.
  - `VaultState` — the on-disk envelope: `salt`, `nonce`, `cipher`.
- **`ports.rs`** — Pure trait definitions:
  - `CryptoPort` — `salt_gen`, `init`, `reset`, `encrypt`, `decrypt`
  - `StoragePort` — `exists`, `set_path`, `get_path`, `load`, `save`, `list_vaults`
- **`errors.rs`** — Typed error hierarchy:
  - `VaultError` — top-level (wraps `CryptoError` and `StorageError`)
  - `CryptoError` — adapter-level crypto failures
  - `StorageError` — adapter-level I/O failures

No external dependencies (only `serde`, `zeroize`, `thiserror`, `chrono`, `wincode`).

---

### `application/`

The orchestration layer. `VaultEngine<S, C>` is generic over any `StoragePort` and `CryptoPort` implementation.

```
VaultEngine<S: StoragePort, C: CryptoPort>
├── storage: S
├── crypto: C
├── vault_state: Option<VaultState>   // None = locked
├── entries: BTreeMap<String, Entry>  // in-memory decrypted entries
└── dirty: bool                       // true = uncommitted changes
```

#### Operations

| Method | Description |
|--------|-------------|
| `create_vault(name, pw)` | Generates salt, derives key, commits empty state to disk |
| `unlock(name, pw)` | Loads file, derives key, decrypts entries into memory |
| `lock()` | Zeroizes entries, clears vault state |
| `commit()` | Encrypts current entries, saves to disk with fresh nonce |
| `add(svc, user, pw)` | Inserts a new `Entry`, marks dirty |
| `delete(svc)` | Removes entry (marks dirty only on success) |
| `get(svc)` | Returns a reference to an entry |
| `get_entries()` | Returns sorted list of service names |
| `get_vaults()` | Delegates to `StoragePort::list_vaults` |

---

### `adapters/aes_crypto.rs`

Implements `CryptoPort` using:

- **`Argon2::default()`** (Argon2id) for key derivation from password + salt
- **`Aes256Gcm`** from the `aes-gcm` crate for AEAD encryption
- A fresh **random nonce** (via `OsRng`) on every `encrypt` call
- `ZeroizeOnDrop` on the key field — automatically wiped when dropped
- `reset()` — explicitly zeroizes the key without dropping the struct (used after failed unlock)

---

### `adapters/file_storage.rs`

Implements `StoragePort` using the local filesystem under `~/.vault/`.

#### Write Protocol (defensive)

```
1. Ensure ~/.vault/ directory exists
2. If vault file already exists:
   a. Copy it to <name>.bkp
   b. SHA-256 hash both files
   c. Abort with IntegrityError if hashes differ
3. Write new content to <name>.vault
4. fsync the file
5. If write fails: restore from .bkp
```

#### `get_path()` — returns the vault **stem** (e.g. `"personal"`), not the full filesystem path, so the prompt displays cleanly.

---

### `adapters/cli/`

The outermost layer. Implements the interactive REPL.

- **`VaultCli<S, C>`** wraps the engine and a `rustyline::Editor` for line editing.
- **`run()`** — main loop: reads input → parses command → dispatches to `handle_command`.
- **`confirm_exit()` / `confirm_lock()`** — when `dirty = true`, prompts the user to commit/discard before proceeding.
- **`VaultHelper`** — implements `rustyline::Completer` for tab-completion. Only the current token (from last space to cursor) is matched and replaced.
- Passwords are read with `rpassword` (no echo).

---

## Data Flow: `commit`

```
entries: BTreeMap<String, Entry>
    │
    ▼ wincode::serialize_into()
entries_buffer: Vec<u8>
    │
    ▼ CryptoPort::encrypt()
(cipher: Vec<u8>, nonce: [u8; 12])
    │
    ▼ written into VaultState { salt, nonce, cipher }
    │
    ▼ wincode::serialize_into()
vault_buffer: Vec<u8>
    │
    ▼ StoragePort::save()  (backup + fsync)
~/.vault/<name>.vault
```

## Data Flow: `unlock`

```
~/.vault/<name>.vault
    │
    ▼ StoragePort::load()
vault_buffer: Vec<u8>
    │
    ▼ wincode::deserialize_from()
VaultState { salt, nonce, cipher }
    │
    ├──► CryptoPort::init(password, salt)   → derives AES key
    │
    ▼ CryptoPort::decrypt(cipher, nonce)
entries_buffer: Vec<u8>
    │
    ▼ wincode::deserialize_from()
entries: BTreeMap<String, Entry>
```
