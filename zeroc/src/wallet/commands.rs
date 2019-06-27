use std::path::PathBuf;
use crate::term::Term;
use crate::config::get_default_keystore_dir;
use super::{WalletDirectory, KeystoreDirectory, Result, KeyFile, DirOperations};
use super::config::{MASTER_KEYFILE, VERSION, ITERS, KEYSTORE_DIRECTORY};
use bip39::{Mnemonic, Language, MnemonicType};
use rand::Rng;

/// Create a new wallet
pub fn new_wallet<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
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
    let phrase = mnemonic.into_phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.simply(&format!("{}\n", phrase))?;

    // 5. create master keyfile
    let mut keyfile_master = KeyFile::create_master(MASTER_KEYFILE, VERSION, &password[..], ITERS, rng)?;

    // 6. store master keyfile
    keystore_dir.insert(&mut keyfile_master, rng)?;

    Ok(())
}