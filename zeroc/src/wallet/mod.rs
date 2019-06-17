use std::{
    collections::HashMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use self::error::Result;

mod commands;
mod config;
mod error;


#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountName(String);

pub struct Encrypted();

/// Wallet object
pub struct Wallet {
    // pub name: WalletName,
    pub encrypted_keys: HashMap<AccountName, Vec<u8>>,
    pub root_dir: PathBuf,
    pub current_index: ,
    pub account_name_map: 
    pub config: config::Config;
}

impl Wallet {
    pub fn new<P: AsRef<Path>>(
        root_dir: P,
        config: config::Config,
        account_name: AccountName,
        encrypted_key: Vec<u8>,
    ) -> Self {
        Wallet {
            encrypted_key: HashMap::new(),
            root_dir: root_dir,
            config: config,
        }
    }

    pub fn save(
        &self,
        account_name: AccountName,
        encrypted_key: Vec<u8>
    ) -> Result<()>
    {

    }

    fn save_internal(&self) -> Result<()> {
        let dir = config::get_a_wallet_dir(self.root_dir.clone(), &self.name.0);
        fs::DirBuilder::new().recursive(true).create(dir.clone())?;

        // 1. save the configuration file


        // 2. save the encrypted key

        // 3. (Optional) save the public key

        Ok(())
    }

    pub fn load() -> Self {

    }
}