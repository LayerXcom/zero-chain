use std::path::{Path, PathBuf};

pub const KEYSTORE_DIRECTORY: &'static str = "keystore";
pub const MASTER_KEYFILE: &'static str = "master";
pub const VERSION: u32 = 1;
pub const ITERS: u32 = 1024;

/// Get the path to directory where all wallets are stored.
pub fn get_keystore_dir<P: AsRef<Path>>(root_dir: P) -> PathBuf {
    root_dir.as_ref().join(KEYSTORE_DIRECTORY)
}

/// Get the path to directory where a provided name's wallet is stored.
pub fn get_a_wallet_dir<P: AsRef<Path>>(root_dir: P, name: &str) -> PathBuf {
    root_dir.as_ref().join(KEYSTORE_DIRECTORY).join(name)
}

// pub fn get_unique_filename()
