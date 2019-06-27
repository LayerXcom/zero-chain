use std::path::PathBuf;
use crate::term::Term;
use super::{WalletDirectory, KeystoreDirectory, DirOperations};
use super::keyfile::{KeyFile, IndexFile};
use super::error::Result;
use super::config::*;
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
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path, &wallet_dir)?;

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

    // 7. store new indexfile
    new_indexfile(&wallet_dir)?;




    Ok(())
}

fn new_keyfile<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
    keystore_dir: &KeystoreDirectory,
) -> Result<()> {

    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.passowrd("wallet password")?;

    // enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    let master_keyfile = keystore_dir.load_master()?;
    

    // create new keyfile
    // let mut keyfile = KeyFile::new(account_name.as_str(), VERSION, &password[..], ITERS, xsk: &ExtendedSpendingKey, rng)?;

    Ok(())
}

/// Create a new index file in wallet directory.
fn new_indexfile(wallet_dir: &WalletDirectory) -> Result<()> {
    let mut indexfile: IndexFile = Default::default();
    wallet_dir.insert_indexfile(&mut indexfile)?;

    Ok(())
}
