# Backlog

One item at a time: implement → test → commit. Tick the box in the commit that finishes the item.

Severity: 🔴 high · 🟠 medium · 🟡 low

## Suggested order

1. **T0**: test suite
2. Small, isolated fixes: B1, B5, B10, B12
3. F1 + F2 (with B4): both touch the CLI input layer
4. B2 + B7 + B8: safe writes
5. E1, then F3 and X3 (they need the new file format)
6. Remaining items, in any order

## Foundation

- [x] **T0** Test suite (see `docs/TESTING.md`): unit tests per area in `src/tests/`, end-to-end tests in a pseudo-terminal in `tests/e2e/`, a v0 vault fixture, and `#[ignore]`d tests for the open bugs. Every later item adds its own tests.

## Bugs and hardening

- [x] 🔴 **B1** `rename` silently overwrites an existing vault (and its `.bkp`): `fs::rename` replaces the destination.
- [x] 🔴 **B2** Non-atomic save (truncates in place, `.bkp` not fsynced, restore only on in-process errors) and no lock against two sessions on the same vault (the last commit wins).
- [x] 🔴 **B3** A vault whose payload exceeds 4 MiB commits but never opens again (wincode's default read limit). Fix together with E1.
- [x] 🟠 **B4** Sub-prompts (`update` username, confirmations, exit menu) use raw `read_line`: arrow keys are stored in the field as escape sequences.
- [x] 🟠 **B5** `AesGcmCrypto::reset()` zeroizes a copy of the key and leaves the original bytes in place.
- [x] 🟠 **B6** CSV import maps columns by position (ignores the header), is not atomic (an error mid-file leaves partial entries with `dirty = false`) and accepts service names with spaces that the CLI can't reach.
- [x] 🟠 **B7** Permissions: CSV export follows the umask and overwrites existing files; `~/.vault` isn't `0700`. (Vaults created before the `0600` change now become `0600` on their next commit, thanks to B2's atomic save.)
- [x] 🟠 **B8** After `passwd`, the `.bkp` still opens with the old password until the next commit.
- [x] 🟠 **B9** Empty or weak master passwords are accepted (`create`, `passwd`).
- [x] 🟡 **B10** `gen` has no upper bound: `gen 99999999999` aborts the process and loses uncommitted changes.
- [x] 🟡 **B11** Incomplete zeroization: removed entry dropped on `rm`, no wipe on exit without `lock`, `serialize_into` reallocations, `zeroize` features of `argon2`/`aes-gcm` off, first password leaked when the second prompt fails, `Entry` derives `Debug`.
- [x] 🟡 **B12** `clear` doesn't clear the scrollback (`\x1b[3J`), so passwords shown by `get` stay in the terminal history.
- [ ] 🟡 **B13** Docs out of date: MSRV is 1.88 (let chains), placeholder clone URL, Wayland and `0o600` claims, missing ports/operations/dependencies, nonce birthday bound, zeroization and crash-safety claims. Add a warning against round-tripping CSV exports through spreadsheets (they drop leading zeros).
- [x] 🟡 **B15** Dependencies: replace `dirs-2` with `std::env::home_dir`; turn off `arboard` default features (they pull `image`, `png`, `tiff`).

## Features

- [x] **F1** Context-aware Tab completion: commands in the first word, entry names after `get`/`copy`/`rm`/`update`, vault names after `unlock`/`drop`, file paths after `import`/`export`. Fixes commands being suggested at any position.
- [x] **F2** Interactive selector: browse entries with ↑/↓, fuzzy filter while typing, Enter to act (copy, show, …).
- [x] **F3** Description/notes on entries. Needs E1.

## Essentials

- [x] **E1** Versioned file format: magic, version and Argon2 parameters in a header authenticated as AES-GCM AAD; automatic migration of existing vaults; stronger Argon2 parameters; no 4 MiB limit (B3).
- [x] **E2** Clipboard: clear automatically after ~30 s and stay out of clipboard-manager history.
- [x] **E3** Auto-lock after N minutes of inactivity.
- [x] **E5** Rename an entry (`mv <old> <new>`).
- [ ] **E6** Quoted arguments, so names can contain spaces (`add "My Bank" joao`).
- [x] **E7** `copy <svc> user` to copy the username.
- [ ] **E8** `status` (changes since the last commit) and `discard` (drop uncommitted changes without locking).
- [ ] **E9** `restore` from the `.bkp`.
- [ ] **E10** Generator options: no symbols, no ambiguous characters, passphrases.
- [x] **E11** Disable core dumps and same-user ptrace (`prctl(PR_SET_DUMPABLE, 0)`).

## Extras

- [ ] **X2** Lean health report: reused and short passwords (age as information only).
- [x] **X3** Password history per entry (last N passwords with dates). Needs E1.

## Dropped

- **B14** Leading zeros: not a vault bug; the CSV went through a spreadsheet before the import (warning goes in B13).
- **E4** Search: covered by F2's fuzzy filter.
- **X1** TOTP: puts both factors in the same file.
- **X4** Tags/folders: multiple vaults plus F2 cover it.
- **X5** Custom fields: F3 notes cover it.
- **X6** Keyfile: no gain while it sits on the same disk as the vault.
- **X7** Non-interactive mode: without an agent, every call asks for the master password again. Revisit if scripting becomes a need.
- **X8** Interactive selector: became F2.
- **X9** Encrypted backup: the `.vault` file already is one.
