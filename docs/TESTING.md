# Testing

`cargo test` runs the whole suite in a few seconds once it's built. Nothing touches your real `~/.vault`: unit tests work in temporary directories, and the end-to-end tests run the binary with `$HOME` pointing at one.

## Layout

```text
src/tests/                unit and component tests of the crate internals
├── support.rs            TempDir and engine helpers, the cheap test KDF cost
├── domain.rs             Entry (history, notes, wiping, redacted Debug), KdfParams
├── format.rs             the file format byte by byte: every version, plaintext codec
├── generator.rs          generated passwords and passphrases, with counting "randomness"
├── health.rs             the health report: reused, short and oldest passwords
├── crypto.rs             AesGcmCrypto: key derivation, AES-GCM, random numbers
├── storage.rs            FileStorage: files, backups, atomic saves, sessions
├── engine.rs             VaultEngine flows with the real adapters, upgrades
├── cli.rs                command parser, Tab completion, ~ expansion
├── clipboard.rs          the clipboard for secrets, on a fake clipboard
└── compat.rs             old vault files: opens (and upgrades) the fixtures

tests/e2e/                the real binary in a pseudo-terminal (Unix only)
├── support.rs            the harness: Session, TempDir, key codes
├── flows.rs              everyday flows: create, add, commit, exit menu, passwd…
├── editing.rs            line editing: Tab, history, cursor keys, Ctrl-C, Ctrl-D
├── selector.rs           the find selector: arrows, fuzzy filter, action menu
└── process.rs            the process: no core dumps, no same-user memory reads (Linux)

tests/fixtures/v0.vault   a vault from before the versioned format
tests/fixtures/v1.vault   a vault in format v1
tests/fixtures/v2.vault   a vault in format v2, with notes
tests/fixtures/v3.vault   a vault in format v3, with notes and a password history
```

## Running

| Command | Runs |
|---------|------|
| `cargo test` | everything |
| `cargo test --bin vault` | unit tests only |
| `cargo test --test e2e` | end-to-end tests only |
| `cargo test engine::` | tests whose path contains `engine::` |

CI (`.github/workflows/ci.yml`) runs `cargo test` and clippy on every push to `develop` or `main` and on every pull request, and checks that the crate still builds on Rust 1.89, the `rust-version` in `Cargo.toml`. The release workflow runs the tests again before building.

## Conventions

- **Every change ships with tests**, in the module of its area, and in `tests/e2e/` if it shows up in the terminal.
- **A bug fix starts with the test that shows the bug.** Write it first, watch it fail, then fix: the test proves the bug existed and stays as its regression test. Bugs are tracked in GitHub issues, and the fix's commit closes its issue (`fixes #12`). A test describes the behaviour wanted; when more than one fix is acceptable (refusing an operation instead of handling it, say), it accepts any of them and checks the invariant.
- **Never regenerate the fixtures.** Each `tests/fixtures/vN.vault` proves that vaults written in format N still open. When the format changes again, add a `v4.vault` with the same entries and keep every older test. The password and the expected entries are in `src/tests/compat.rs`.
- **End-to-end tests type like a user.** `Session::command` waits for the prompt and runs a line, `answer` replies to a sub-prompt (password, y/N, the exit menu), `output` returns what the last command printed, and `expect` waits for any text. Escape sequences are stripped before matching. `Session::start_with` passes environment variables (`VAULT_AUTO_LOCK` for the auto-lock tests); otherwise it is unset, so the default applies.
- **Break it on purpose before committing.** For each change, mutate the new code (drop a check, swap a branch, off-by-one a bound) and make sure some test fails; a mutant that survives means a missing test, or code that does nothing.

## Speed

- **Unit tests derive keys at a tiny cost** (`support::CHEAP`: real Argon2id, 64 KiB, one pass), through `VaultEngine::with_kdf`. They take about 3–4 s, most of it one test that round-trips a 5 MiB vault through AES-GCM in a debug build.
- **End-to-end tests use the real cost** (128 MiB, 3 passes) because they run the shipped binary; with the auto-lock tests waiting a few seconds, they take about 7 s.
- `argon2` and `blake2` are compiled with optimisations even in debug builds (see `Cargo.toml`); without that, every derivation would be 10–20× slower.
