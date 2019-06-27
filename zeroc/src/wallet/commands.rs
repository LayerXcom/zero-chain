use std::path::PathBuf;
use crate::term::Term;
use crate::config::get_default_keystore_dir;
use super::error::Result;
use super::disk::{WalletDirectory, KeystoreDirectory};
use bip39::{Mnemonic, Language, MnemonicType};

/// Create a new wallet
pub fn new(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<()> {

    // 1. configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // 2. configure ketstore directory
    let keystore_dir_path = get_default_keystore_dir(&wallet_dir.0);
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path, wallet_dir)?;

    // 3. configure user-defined passoword
    term.info("Set a wallet password. This is for local usage only, allows you to protect your cached private key and prevent from creating non desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 4. generate the mnemonics
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);

    // 2.


    unimplemented!();
}