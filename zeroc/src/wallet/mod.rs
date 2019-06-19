use std::{
    collections::HashMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use self::error::Result;
use crate::derive::{ChildIndex, EncryptionKeyBytes};

mod commands;
mod config;
mod keyfile;
mod error;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountName(String);

/// Wallet object
pub struct Wallet {
    // pub root_dir: PathBuf,
    pub enc_master_key: Vec<u8>,
    pub account_name_map: HashMap<ChildIndex, (AccountName, Option<EncryptionKeyBytes>)>,
    pub default_index: ChildIndex,
    // pub config: config::Config;
}

impl Wallet {
    /// Create a new wallet. The master key is expected to have been properly encrypted.
    /// When a new wallet is created, a new hardened derived account is also generated.
    pub fn init<P: AsRef<Path>>(
        root_dir: P,
        enc_master_key: Vec<u8>,
        account_name: AccountName,
        enc_key_bytes: Option<EncryptionKeyBytes>,
    ) -> Result<Self> {

        unimplemented!();

        // Wallet {
        //     enc_master_key: HashMap::new(),
        //     root_dir: root_dir,
        //     config: config,
        // }
    }

    pub fn create_account(&self) -> Result<()> {
        unimplemented!();
    }

    pub fn change_default_account(&self) -> Result<()> {
        unimplemented!();
    }

    pub fn list() -> Self {
        unimplemented!();
    }

    pub fn destroy(self) -> Result<()> {
        unimplemented!();
    }

    fn load<P: AsRef<Path>>(root_dir: P) -> Result<Self> {
        unimplemented!();
    }

    fn save<P: AsRef<Path>>(
        &self,
        root_dir: P,
        account_name: AccountName,
        encrypted_key: Vec<u8>
    ) -> Result<()>
    {
        let wallet_file = fs::File::create(root_dir)?;




        // 1. save the configuration file


        // 2. save the encrypted key

        // 3. (Optional) save the public key

        Ok(())
    }
}