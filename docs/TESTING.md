# Testing

`cargo test` runs the whole suite in about a second once it's built. Nothing touches your real `~/.vault`: unit tests work in temporary directories, and the end-to-end tests run the binary with `$HOME` pointing at one.

## Layout

```text
src/tests/                unit and component tests of the crate internals
├── support.rs            TempDir and engine helpers
├── domain.rs             Entry, VaultState
├── crypto.rs             AesGcmCrypto: key derivation, AES-GCM, generator
├── storage.rs            FileStorage: files, backups, listing, rename, delete
├── engine.rs             VaultEngine flows with the real adapters
├── cli.rs                command parser, Tab completion, ~ expansion
├── compat.rs             on-disk format; opens tests/fixtures/v0.vault
└── known_bugs.rs         open bugs from BACKLOG.md, #[ignore]d

tests/e2e/                the real binary in a pseudo-terminal (Unix only)
├── support.rs            the harness: Session, TempDir, key codes
├── flows.rs              everyday flows: create, add, commit, exit menu, passwd…
├── editing.rs            line editing: Tab, history, cursor keys, Ctrl-C, Ctrl-D
├── selector.rs           the find selector: arrows, fuzzy filter, action menu
└── known_bugs.rs         open bugs that only show up in a terminal, #[ignore]d

tests/fixtures/v0.vault   a vault written in the current (v0) format
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
- **Never regenerate `tests/fixtures/v0.vault`.** It proves that vaults written by older versions still open. When the format changes (E1), add a new fixture next to it and keep both tests. Its password is in `src/tests/compat.rs`.
- **End-to-end tests type like a user.** `Session::command` waits for the prompt and runs a line, `answer` replies to a sub-prompt (password, y/N, the exit menu), `output` returns what the last command printed, and `expect` waits for any text. Escape sequences are stripped before matching.

## Speed

`argon2` and `blake2` are compiled with optimisations even in debug builds (see `Cargo.toml`). Without that, key derivation alone made the suite take 10–15 s instead of under one. When E1 raises the Argon2 cost, the tests should switch to cheap parameters instead.
