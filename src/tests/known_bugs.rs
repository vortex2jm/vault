//! Bugs still open in `BACKLOG.md`, written as the behaviour we want.
//!
//! They are `#[ignore]`d so `cargo test` stays green; `cargo test -- --ignored`
//! shows which ones are still broken. When an item is fixed, remove its
//! `#[ignore]` and move the test to the module of its area.
//!
//! Where several fixes are acceptable (e.g. refusing an operation instead of
//! handling it), the test accepts any of them and checks the invariant.
//!
//! None open right now.
