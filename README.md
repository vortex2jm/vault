# 🔐 Vault

A local, offline CLI password manager written in Rust. Vault stores your credentials in encrypted files on disk using **AES-256-GCM** and derives keys with **Argon2id** — so your master password never leaves your machine.

---

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (memory-hard, resistant to brute force)
- **Multiple named vaults** — one per context (work, personal, etc.)
- **Tab-completion** and **command history** in the interactive shell
- **Automatic backup + SHA-256 integrity check** before every write
- **Memory zeroization** on lock — secrets never linger
- **Zero network access** — entirely offline

---

## Requirements

- Rust toolchain ≥ 1.85 (edition 2024)

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

```
--- Vault CLI ---

vault[locked]> create personal
New vault password: ••••••••
Vault 'personal' created.

vault[personal|0]> add github myuser
Service password: ••••••••
Entry 'github' added.

vault[personal*|1]> commit
Changes committed.

vault[personal|1]> get github
github
  user: myuser
  pass: mysecretpassword

vault[personal|1]> lock
Vault locked.

vault[locked]>
```

---

## Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `create` | `<name>` | Create a new vault |
| `unlock` | `<name>` | Unlock an existing vault |
| `lock` | — | Lock the current vault |
| `add` | `<service> <username>` | Add a credential entry |
| `get` | `<service>` | Show a credential entry |
| `rm` | `<service>` | Remove a credential entry |
| `commit` | — | Save changes to disk |
| `ls` / `list` | — | List vaults (locked) or entries (unlocked) |
| `clear` | — | Clear the terminal |
| `help` | — | Print help |
| `exit` | — | Exit (prompts to commit if there are unsaved changes) |

---

## Prompt Legend

```
vault[locked]>                    # vault is locked
vault[myname|3]>                  # unlocked, 3 entries
vault[myname*|3]>                 # unlocked, unsaved changes
```

---

## Storage Layout

All vault files are stored in `~/.vault/`:

```
~/.vault/
├── personal.vault     # encrypted vault
├── personal.bkp       # backup (created before each write)
└── work.vault
```

Each `.vault` file is a binary-serialized `VaultState` containing:

- `salt` — 16-byte random salt (generated at creation)
- `nonce` — 12-byte AES-GCM nonce (random, refreshed on every commit)
- `cipher` — AES-256-GCM ciphertext of the serialized entries map

---

## Further Reading

- [Architecture](docs/ARCHITECTURE.md) — module design, data flow, hexagonal pattern
- [Security Model](docs/SECURITY.md) — cryptographic choices, threat model, limitations
