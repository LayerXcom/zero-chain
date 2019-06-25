use std::{
    collections::HashMap,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use rand::Rng;
use self::error::Result;
use crate::derive::{ChildIndex, EncryptionKeyBytes, ExtendedSpendingKey};

mod commands;
mod config;
mod keyfile;
mod error;
mod disk;
pub use keyfile::{SerdeBytes, KeyFile};

/// Operations in a keystore directory
pub trait DirOperations {
    /// Insert a new keyfile to this keystore directory.
    fn insert<R: Rng>(&self, keyfile: &mut KeyFile, rng: &mut R) -> Result<()>;

    /// Load all keyfiles in this keystore directory.
    fn load_all(&self) -> Result<Vec<KeyFile>>;

    /// Remove a keyfile from this keystore directory.
    fn remove(&self, keyfile: &mut KeyFile) -> Result<()>;
}


/// Wallet object
pub struct Wallet {
    // pub enc_master_key: Vec<u8>,
    // pub account_name_map: HashMap<ChildIndex, (AccountName, Option<EncryptionKeyBytes>)>,
    // pub default_index: ChildIndex,
    // pub config: config::Config;
    pub keyfile: KeyFile,
}

impl Wallet {
    /// Create a new wallet. The master key is expected to have been properly encrypted.
    /// When a new wallet is created, a new hardened derived account is also generated.
    pub fn init<P: AsRef<Path>, R: Rng>(
        rng: &mut R,
        root_dir: P,
        version: u32,
        account_name: String,
    ) -> Result<Self> {
        let seed: [u8; 32] = rng.gen();
        // let extended_spending_key = ExtendedSpendingKey::master(&seed);



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
        account_name: String,
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