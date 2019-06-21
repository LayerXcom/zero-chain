use super::WalletDirectory;
use std::path::{PathBuf, Path};

pub struct DiskDirectory<P: AsRef<Path>>{
    path: P,
}

