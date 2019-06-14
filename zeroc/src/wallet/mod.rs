mod commands;
mod config;
mod error;

use self::error::Result;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletName(String);

pub struct Wallet {

    pub encrypted_key: Vec<u8>,
    pub root_dir: PathBuf,
    pub config: config::Config;
}

impl Wallet {
    pub fn new<P: AsRef<Path>>(

    ) -> Self {

    }

    pub fn save(&self) -> Result<()> {

    }

    fn save_internal(&self) -> Result<()> {
        let dir = config::
    }
}