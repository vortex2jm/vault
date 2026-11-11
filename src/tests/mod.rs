//! Unit and component tests for the crate internals, one module per area.
//! End-to-end tests that drive the real binary live in `tests/e2e/`.
//! See `docs/TESTING.md`.

mod support;

mod cli;
mod clipboard;
mod compat;
mod crypto;
mod domain;
mod engine;
mod format;
mod generator;
mod health;
mod storage;
