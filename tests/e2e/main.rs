//! End-to-end tests: run the real `vault` binary in a pseudo-terminal and type
//! into it like a user would. Unit tests live in `src/tests/`; see
//! `docs/TESTING.md`.
#![cfg(unix)]

mod support;

mod editing;
mod flows;
mod known_bugs;
mod selector;
