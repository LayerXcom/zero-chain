use std::path::{Path, PathBuf};

pub const WALLETS_DIRECTORY: &'static str = "wallets";

/// Get the path to directory where all wallets are stored.
pub fn get_wallets_dir<P: AsRef<Path>>(root_dir: P) -> PathBuf {
    root_dir.as_ref().join(WALLETS_DIRECTORY)
}

/// Get the path to directory where a provided name's wallet is stored.
pub fn get_a_wallet_dir<P: AsRef<Path>>(root_dir: P, name: &str) -> PathBuf {
    root_dir.as_ref().join(WALLETS_DIRECTORY).join(name)
}
