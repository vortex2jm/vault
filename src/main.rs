use crate::{
    adapters::{aes_crypto::AesGcmCrypto, cli::VaultCli, file_storage::FileStorage},
    application::engine::VaultEngine,
};

mod adapters;
mod application;
mod domain;

fn main() -> anyhow::Result<()> {    
    let storage = FileStorage::new();
    let crypto = AesGcmCrypto::new();
    let engine = VaultEngine::new(storage, crypto);

    let mut cli = VaultCli::new(engine)?;
    cli.run()
}
