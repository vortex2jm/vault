# Testing

`cargo test` runs the whole suite in a few seconds once it's built. Nothing touches your real `~/.vault`: unit tests work in temporary directories, and the end-to-end tests run the binary with `$HOME` pointing at one.

## Layout

```text
src/tests/                unit and component tests of the crate internals
├── support.rs            TempDir and engine helpers, the cheap test KDF cost
├── domain.rs             Entry, KdfParams
├── format.rs             the file format byte by byte: every version, plaintext codec
├── crypto.rs             AesGcmCrypto: key derivation, AES-GCM, generator
├── storage.rs            FileStorage: files, backups, atomic saves, sessions
├── engine.rs             VaultEngine flows with the real adapters, upgrades
├── cli.rs                command parser, Tab completion, ~ expansion
├── compat.rs             old vault files: opens (and upgrades) the fixtures
└── known_bugs.rs         open bugs from BACKLOG.md, #[ignore]d

tests/e2e/                the real binary in a pseudo-terminal (Unix only)
├── support.rs            the harness: Session, TempDir, key codes
├── flows.rs              everyday flows: create, add, commit, exit menu, passwd…
├── editing.rs            line editing: Tab, history, cursor keys, Ctrl-C, Ctrl-D
├── selector.rs           the find selector: arrows, fuzzy filter, action menu
└── known_bugs.rs         open bugs that only show up in a terminal, #[ignore]d

tests/fixtures/v0.vault   a vault from before the versioned format
tests/fixtures/v1.vault   a vault in format v1
tests/fixtures/v2.vault   a vault in format v2, with notes
tests/fixtures/v3.vault   a vault in format v3, with notes and a password history
```

## Running

| Command | Runs |
|---------|------|
| `cargo test` | everything except the known bugs |
| `cargo test --bin vault` | unit tests only |
| `cargo test --test e2e` | end-to-end tests only |
| `cargo test engine::` | tests whose path contains `engine::` |
| `cargo test -- --ignored` | only the known bugs (expected to fail) |

## Conventions

- **Every backlog item ships with tests.** A bug fix makes its `known_bugs` test pass: remove the `#[ignore]` and move the test to the module of its area, in the commit that ticks the item in `BACKLOG.md`. A feature adds tests to the module of its area, and to `tests/e2e/` if it shows up in the terminal.
- **Known-bug tests describe the behaviour we want**, not the current one. When more than one fix is acceptable (refusing an operation instead of handling it, say), the test accepts any of them and checks the invariant.
- **Never regenerate the fixtures.** Each `tests/fixtures/vN.vault` proves that vaults written in format N still open. When the format changes again, add a `v4.vault` with the same entries and keep every older test. The password and the expected entries are in `src/tests/compat.rs`.
- **End-to-end tests type like a user.** `Session::command` waits for the prompt and runs a line, `answer` replies to a sub-prompt (password, y/N, the exit menu), `output` returns what the last command printed, and `expect` waits for any text. Escape sequences are stripped before matching.

## Speed

- **Unit tests derive keys at a tiny cost** (`support::CHEAP`: real Argon2id, 64 KiB, one pass), through `VaultEngine::with_kdf`. They take about 2.5 s, almost all of it one test that round-trips a 5 MiB vault through AES-GCM in a debug build.
- **End-to-end tests use the real cost** (128 MiB, 3 passes) because they run the shipped binary, so they take about 4 s.
- `argon2` and `blake2` are compiled with optimisations even in debug builds (see `Cargo.toml`); without that, every derivation would be 10–20× slower.
