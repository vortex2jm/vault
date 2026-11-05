use crate::{
    adapters::{aes_crypto::AesGcmCrypto, cli::VaultCli, file_storage::FileStorage, process},
    application::engine::VaultEngine,
};

mod adapters;
mod application;
mod domain;

#[cfg(test)]
mod tests;

fn main() -> anyhow::Result<()> {
    // Before any secret is read.
    if let Err(e) = process::harden() {
        eprintln!("Warning: could not turn off core dumps and debugging ({e}).");
    }
    let storage = FileStorage::new()?;
    let crypto = AesGcmCrypto::new();
    let engine = VaultEngine::new(storage, crypto);

    let mut cli = VaultCli::new(engine)?;
    cli.run()
}
