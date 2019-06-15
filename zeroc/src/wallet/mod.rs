use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use self::error::Result;

mod commands;
mod config;
mod error;


#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletName(String);

/// Wallet object
pub struct Wallet {
    pub name: WalletName,
    pub encrypted_key: Vec<u8>,
    pub root_dir: PathBuf,
    pub config: config::Config;
}

impl Wallet {
    pub fn new<P: AsRef<Path>>(
        root_dir: P,
        name: WalletName,
        config: config::Config,
        encrypted_key: Vec<u8>,
    ) -> Self {
        Wallet {
            name: name,
            encrypted_key: Vec<u8>,
            root_dir: root_dir,
            config: config,
        }
    }

    pub fn save(&self) -> Result<()> {

    }

    fn save_internal(&self) -> Result<()> {
        let dir = config::get_a_wallet_dir(self.root_dir.clone(), &self.name.0);
        fs::DirBuilder::new().recursive(true).create(dir.clone())?;

        // 1. save the configuration file


        // 2. save the encrypted key

        // 3. (Optional) save the public key

        Ok(())
    }
}