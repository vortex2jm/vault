# 🔐 Vault

A local, offline CLI password manager written in Rust. Vault stores your credentials in encrypted files on disk using **AES-256-GCM** and derives keys with **Argon2id** — so your master password never leaves your machine.

---

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (memory-hard, resistant to brute force)
- **Multiple named vaults** — one per context (work, personal, etc.)
- **Tab-completion** and **command history** in the interactive shell
- **Automatic backup + SHA-256 integrity check** before every write
- **Strict Security**: Memory zeroization (secrets never linger), `0o600` restrictive file permissions (Unix), and path traversal protection.
- **Zero network access** — entirely offline

---

## Requirements

- Rust toolchain ≥ 1.85 (edition 2024)
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
Entry 'github' added.

vault[personal*|1]> commit
Changes committed.

vault[personal|1]> copy github
Password for 'github' copied to clipboard.

vault[personal|1]> lock
Vault locked.

vault[locked]>
```

---

## Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| **Core** |
| `create` | `<name>` | Create a new vault (asks for password twice) |
| `unlock` | `<name>` | Unlock an existing vault |
| `lock` | — | Lock the current vault |
| `passwd` | — | Change the current vault's master password |
| `drop` | `<name>` | Permanently delete a vault and its backup (vault must be locked) |
| **Entries** |
| `add` | `<service> <user>` | Add a credential entry |
| `get` | `<service>` | Show a credential entry (username and password) |
| `copy` | `<service>` | Copy a password directly to the OS clipboard |
| `update` | `<service>` | Update username/password of an entry (leave blank to keep current) |
| `rm` | `<service>` | Remove a credential entry |
| `gen` | `[length]` | Generate a random strong password (default: 20 chars) |
| **Data & I/O** |
| `commit` | — | Save changes to disk |
| `rename` | `<new_name>`| Rename the current vault file |
| `ls`/`list`| — | List vaults (when locked) or entries (when unlocked) |
| `info` | — | Show vault path and entry count |
| `export` | `<path>` | Export entries to a CSV file (**Warning: Plaintext!**) |
| `import` | `<path>` | Import entries from a CSV file (merges new services) |
| **CLI** |
| `clear` | — | Clear the terminal screen |
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

## Storage Layout

All vault files are stored in `~/.vault/` (with strict `0o600` permissions on Unix systems):

```text
~/.vault/
├── personal.vault     # encrypted vault
├── personal.bkp       # backup (created before each write)
└── work.vault
```

Each `.vault` file is a binary-serialized `VaultState` containing:

- `salt` — 16-byte random salt (generated at creation or password change)
- `nonce` — 12-byte AES-GCM nonce (random, refreshed on every commit)
- `cipher` — AES-256-GCM ciphertext of the serialized entries map

---

## CSV Export/Import Format

The `export` and `import` commands use standard RFC 4180 CSV files with the following header:

```csv
service,username,password
github,myuser,mysecret123
aws,admin,super_secure!
```

*Note: Importing merges entries. If a service already exists in the vault, the imported row is skipped.*

---

## Further Reading

- [Architecture](docs/ARCHITECTURE.md) — module design, data flow, hexagonal pattern
- [Security Model](docs/SECURITY.md) — cryptographic choices, threat model, limitations
