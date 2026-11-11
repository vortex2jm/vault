# Changelog

Notable changes to vault, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-11

The first official release.

### Vaults

- Named vaults in `~/.vault/`, each one encrypted file: AES-256-GCM, with the key derived by Argon2id (128 MiB, 3 passes) and the file header authenticated.
- A versioned file format (v3) that opens, and upgrades, every older vault.
- Changes stay pending until `commit`: `status` lists them, `discard` drops them, and `restore` brings back the version the last commit replaced.
- Crash-safe saves (temporary file, `fsync`, atomic rename), and sessions that never overwrite what another one committed.
- Auto-lock after 5 minutes at the prompt (`VAULT_AUTO_LOCK`); with uncommitted changes, a warning instead.
- `create`, `unlock`, `lock`, `passwd` (new master passwords need 8 or more characters), `rename`, `drop`, `info` and `ls`.

### Entries

- Service, username, password, notes, and the last 10 passwords with the date each was replaced (`history`).
- `add`, `get`, `update`, `mv` and `rm`, with names that may have spaces (in quotes).
- `find`: an interactive list with a fuzzy filter and an action menu.
- `copy` (the password, or the username with `user`): kept out of clipboard managers' history and cleared after 30 seconds.
- `gen`: passwords, optionally without symbols or look-alike characters, and passphrases from the EFF word list, with their strength in bits.
- `health`: reused and short passwords, and the oldest ones.
- CSV `export` (always a new `0600` file) and `import` (columns found by name, all or nothing).
- Tab completion of commands, entry names, vault names and file paths.

### Security

- The key, the entries and every typed secret are wiped from memory once done with, Argon2's working memory and the AES round keys too. The known gaps are listed in `docs/SECURITY.md`.
- No core dumps; on Linux, other programs of the same user can't attach a debugger or read the process's memory.
- `~/.vault` is `0700` and every file in it `0600`.
