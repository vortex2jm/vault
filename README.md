# 🔐 Vault

A local, offline CLI password manager written in Rust. Vault stores your credentials in encrypted files on disk using **AES-256-GCM** and derives keys with **Argon2id** — so your master password never leaves your machine.

---

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (memory-hard, resistant to brute force): 128 MiB and 3 passes, recorded in each vault so the cost can grow without breaking old vaults
- **Multiple named vaults** — one per context (work, personal, etc.)
- **Tab-completion** of commands, entry names, vault names and file paths, and **command history** in the interactive shell
- **Interactive selector** (`find`): browse your entries with the arrow keys and fuzzy search
- **Notes and password history** on each entry: the last 10 passwords are kept, with the date each one was replaced
- **Auto-lock**: an unlocked vault left alone at the prompt for 5 minutes locks itself (with uncommitted changes it only warns)
- **Careful clipboard**: `copy` keeps the password out of clipboard managers' history and clears it after 30 s
- **Crash-safe saves**: every commit writes a new file and atomically swaps it in, keeping the previous version as a backup
- **Safe across sessions**: open the same vault in two terminals; a commit never overwrites what the other one saved
- **Strict Security**: Memory zeroization (secrets never linger), no core dumps, no debugging or memory reads by your other programs (Linux), owner-only permissions on Unix (`0700` directory; `0600` vaults, backups and exports), and path traversal protection.
- **Zero network access** — entirely offline

---

## Requirements

- Rust toolchain ≥ 1.89 (edition 2024)
- **Linux/Unix**: `x11` or `wayland` clipboard dependencies (for the `copy` command via `arboard`)

---

## Installation

```bash
git clone https://github.com/youruser/vault
cd vault
cargo install --path .
```

Or just build and run locally:

```bash
cargo build --release
./target/release/vault
```

---

## Quick Start

```text
--- Vault CLI ---

vault[locked]> create personal
New vault password: ••••••••
Confirm password: ••••••••
Vault 'personal' created.

vault[personal|0]> gen 16
Generated: K9#mP2$qLv8nW!j&

vault[personal|0]> add github myuser
Service password: ••••••••
Notes (optional): 2FA on my phone
Entry 'github' added.

vault[personal*|1]> commit
Changes committed.

vault[personal|1]> copy github
Password for 'github' copied to clipboard (cleared in 30 s).

vault[personal|1]> lock
Vault locked.

vault[locked]>
```

---

## Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| **Core** |
| `create` | `<name>` | Create a new vault (asks for the password twice; at least 8 characters) |
| `unlock` | `<name>` | Unlock an existing vault |
| `lock` | — | Lock the current vault |
| `passwd` | — | Change the current vault's master password (at least 8 characters) |
| `drop` | `<name>` | Permanently delete a vault and its backup (vault must be locked) |
| **Entries** |
| `add` | `<service> <user>` | Add a credential entry (asks for its password and optional notes) |
| `get` | `<service>` | Show a credential entry (username, password and notes) |
| `find` | `[term]` | Pick an entry from an interactive list (↑/↓ to move, type to filter), then copy, show, update or remove it, or see its history |
| `history` | `<service>` | Show an entry's previous passwords, newest first, with the date each was replaced (the last 10 are kept) |
| `copy` | `<service> [user]` | Copy a password (or, with `user`, the username) to the clipboard, out of clipboard managers' history; cleared after 30 s or when vault exits |
| `update` | `<service>` | Update an entry: blank keeps the username or password; a new password sends the old one to the history; the notes come pre-filled to edit |
| `mv` | `<service> <new>` | Rename an entry (password, notes and history stay) |
| `rm` | `<service>` | Remove a credential entry |
| `gen` | `[length]` | Generate a random strong password (8–256 chars, default: 20) |
| **Data & I/O** |
| `commit` | — | Save changes to disk |
| `status` | — | Show what changed since the last commit (added, removed, renamed, changed fields) |
| `discard` | — | Drop the uncommitted changes, keeping the vault open (asks first) |
| `rename` | `<new_name>`| Rename the current vault file |
| `ls`/`list`| — | List vaults (when locked) or entries (when unlocked) |
| `info` | — | Show the vault name, entry count and key strength |
| `export` | `<path>` | Export entries to a CSV file (**Warning: Plaintext!**). Created `0600`; never overwrites an existing file |
| `import` | `<path>` | Import entries from a CSV file (merges new services; all or nothing, see below) |
| **CLI** |
| `clear` | — | Clear the screen and the scrollback (hides passwords shown by `get`) |
| `help` | — | Print help |
| `exit` | — | Exit (prompts to commit if there are unsaved changes) |

---

## Prompt Legend

```text
vault[locked]>                    # vault is locked
vault[myname|3]>                  # unlocked, 3 entries
vault[myname*|3]>                 # unlocked, unsaved changes
```

---

## Auto-Lock

An unlocked vault left at the prompt for 5 minutes without a command locks itself, wiping the key and the entries from memory. If it has uncommitted changes, it stays open instead and says so once: locking would throw them away, so committing or discarding them is up to you.

Set the time with `VAULT_AUTO_LOCK`, in seconds (`0` turns it off):

```sh
VAULT_AUTO_LOCK=120 vault    # lock after 2 minutes
```

The time only runs at the main prompt: in the middle of a command (a password prompt, the `find` list) nothing locks.

---

## Storage Layout

All vault files are stored in `~/.vault/`. On Unix the directory is `0700` and every file `0600`; if an older version left them more open, they are tightened on the next commit:

```text
~/.vault/
├── .lock              # taken during each commit, so sessions never write at once
├── personal.vault     # encrypted vault
├── personal.bkp       # previous version, kept by each commit
└── work.vault
```

Each `.vault` file (format v3) is a small header followed by the encrypted entries (service, username, password, notes, previous passwords and timestamps):

- `VAULT\0` and the format version;
- the Argon2id cost used for this vault's key (memory, passes, lanes);
- `salt`: 16 random bytes, new at creation and at each password change;
- `nonce`: 12 random bytes, new at every commit;
- the AES-256-GCM ciphertext of the entries. The header is authenticated with it, so changing any byte makes the vault refuse to open.

Vaults written by older versions (v0 to v2) still open. On unlock they are rewritten in the current format, with a stronger key if theirs was cheaper, and the previous file stays as the `.bkp` until the next commit. The byte-level layout is in [docs/SECURITY.md](docs/SECURITY.md#on-disk-format).

---

## CSV Export/Import Format

The `export` and `import` commands use standard RFC 4180 CSV files with a header row:

```csv
service,username,password,notes
github,myuser,mysecret123,
aws,admin,"super,secure!",root account
```

- `import` finds the columns by name, in any order and any case: `service`, `username` and `password` are required, and `notes` is optional (exports from older versions don't have it). Other columns are ignored.
- Every row has as many fields as the header. A field with a comma or a quote must be quoted, as in the `aws` row above.
- Service names can't be empty or contain spaces, since commands take them as one word.
- Import is all or nothing: if a row is invalid, the error names its line and no entry is added.
- Importing merges entries: if a service already exists in the vault, or appears twice in the file, the first version is kept and the other row is skipped.
- The password history is not exported.

---

## Further Reading

- [Architecture](docs/ARCHITECTURE.md) — module design, data flow, hexagonal pattern
- [Security Model](docs/SECURITY.md) — cryptographic choices, threat model, limitations
- [Testing](docs/TESTING.md) — test layout, how to run it, conventions
