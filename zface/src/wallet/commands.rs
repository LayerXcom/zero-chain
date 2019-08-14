use std::path::PathBuf;
use std::collections::HashMap;
use crate::term::Term;
use crate::derive::ChildIndex;
use crate::utils::mnemonics::*;
use crate::error::{Result, KeystoreError};
use super::{WalletDirectory, KeystoreDirectory, DirOperations};
use super::keyfile::{KeyFile, IndexFile};
use super::config::*;
use bip39::{Mnemonic, Language, MnemonicType, Seed};
use rand::Rng;
use proofs::DecryptionKey;
use pairing::bls12_381::Bls12;

/// Create a new wallet
pub fn new_wallet<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
) -> Result<()> {
    // 1. configure wallet directory
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. configure user-defined passoword
    term.info("Set a wallet password. This is for local use only. It allows you to protect your cached private key and prevents the creation of non-desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 3. generate the mnemonics
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    term.info("Please, note carefully the following mnemonic words. They will be needed to recover your wallet.\n")?;
    term.error(&format!("{}\n", phrase))?;

    // 4. create master keyfile
    let master_seed = Seed::new(&mnemonic, "");
    let master_seed_bytes: &[u8] = master_seed.as_bytes();
    let mut keyfile_master = KeyFile::create_master(MASTER_ACCOUNTNAME, VERSION, &password[..], ITERS, rng, master_seed_bytes)?;

    // 5. store master keyfile
    wallet_dir.insert_master(&mut keyfile_master)?;

    // 6. create a genesis keyfile
    let child_index = ChildIndex::from_index(0);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;

    // 7. store a genesis keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    // 8. store new indexfile
    let file_name = keyfile.file_name.expect("Filename should be set.");
    new_indexfile(&wallet_dir, &file_name, &keyfile.account_name)?;

    term.success(&format!(
        "wallet and a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn show_list(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let keyfiles = keystore_dir.load_all()?;
    if keyfiles.len() == 0 {
        term.warn("Not found accounts\n")?;
        return Ok(());
    }

    let default_index = get_default_index(&wallet_dir)? as usize;

    for (i, keyfile) in keyfiles.iter().enumerate() {
        let (name, address) = (&*keyfile.account_name, &*keyfile.ss58_address);
        if i == default_index {
            term.success(&format!("* {}: {}\n", name, address))?;
        } else {
            term.success(&format!("{}: {}\n", name, address))?;
        }
    }

    Ok(())
}

pub fn new_keyfile<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
) -> Result<()> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.passowrd("wallet password")?;

    // save a new keyfile
    let incremented_index = get_max_index(&wallet_dir)? + 1;
    let child_index = ChildIndex::from_index(incremented_index);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;
    keystore_dir.insert(&mut keyfile, rng)?;

    let filename = keyfile.file_name.ok_or(KeystoreError::InvalidKeyfile)?;

    // set index to new account
    increment_indexfile(&wallet_dir, filename.as_str(), keyfile.account_name.as_str())?;

    term.success(&format!(
        "a new account successfully created.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn recover<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    rng: &mut R,
) -> Result<()> {
    // 1. configure wallet directory
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    // 2. Enter mnemonic
    let mnemonic = input_mnemonic_phrase(MnemonicType::Words12, Language::English);

    // 3. Re-set a new passoword
    term.info("Re-set a new wallet password. This is for local usage only, allows you to protect your cached private key and prevent from creating non desired transactions.\n")?;
    let password = term.new_password("wallet password", "confirm wallet password", "password mismatch")?;

    // 4. create master keyfile
    let master_seed = Seed::new(&mnemonic, "");
    let master_seed_bytes: &[u8] = master_seed.as_bytes();
    let mut keyfile_master = KeyFile::create_master(MASTER_ACCOUNTNAME, VERSION, &password[..], ITERS, rng, master_seed_bytes)?;

    // 5. store master keyfile
    wallet_dir.insert_master(&mut keyfile_master)?;

    // 6. create a genesis keyfile
    let child_index = ChildIndex::from_index(0);
    let mut keyfile = get_new_keyfile(term, rng, &password[..], &wallet_dir, child_index)?;

    // 7. store a genesis keyfile
    keystore_dir.insert(&mut keyfile, rng)?;

    // 8. store new indexfile
    let file_name = keyfile.file_name.expect("Filename should be set.");
    new_indexfile(&wallet_dir, &file_name, &keyfile.account_name)?;

    term.success(&format!(
        "Re-generated your wallet from the provided mnemonic successfully.\n
        {}: {}\n\n",
        keyfile.account_name,
        keyfile.ss58_address
    ))?;

    Ok(())
}

pub fn load_dec_key(
    term: &mut Term,
    root_dir: PathBuf,
) -> Result<DecryptionKey<Bls12>> {
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;
    let default_keyfile_name = get_default_keyfile_name(&wallet_dir)?;
    let keyfile = keystore_dir.load(default_keyfile_name.as_str())?;

    // enter password
    term.info("Enter the wallet password.\n")?;
    let password = term.passowrd("wallet password")?;

    let dec_key = keyfile.get_dec_key(&password[..])?;

    Ok(dec_key)
}

pub fn change_default_account(
    root_dir: PathBuf,
    account_name: &str,
) -> Result<()> {
    let (wallet_dir, _) = wallet_keystore_dirs(&root_dir)?;

    let index_file = wallet_dir.load_indexfile()?;
    let index_file_u = index_file.clone();
    let (keyfile_name, index) = index_file
        .map_account_keyfile
        .get(account_name)
        .ok_or(KeystoreError::InvalidKeyfile)?;

    let mut updated_index_file = index_file_u.set_default_index(*index, keyfile_name.as_str(), account_name);
    wallet_dir.update_indexfile(&mut updated_index_file)?;

    Ok(())
}

fn get_new_keyfile<R: Rng>(
    term: &mut Term,
    rng: &mut R,
    password: &[u8],
    wallet_dir: &WalletDirectory,
    child_index: ChildIndex,
) -> Result<KeyFile> {
    let master_keyfile = wallet_dir.load_master()?;
    let xsk_child = master_keyfile.get_child_xsk(&password[..], child_index)?;

    // enter new account name
    term.info("Enter a new account name.\n")?;
    let account_name = term.account_name("new account name")?;

    // create new keyfile
    let keyfile = KeyFile::new(
        account_name.as_str(),
        VERSION,
        password,
        ITERS,
        &xsk_child,
        rng
    )?;

    Ok(keyfile)
}

/// Create a new index file in wallet directory.
fn new_indexfile(wallet_dir: &WalletDirectory, keyfile_name: &str, account_name: &str) -> Result<()> {
    let mut map_account_keyfile = HashMap::new();
    map_account_keyfile.insert(account_name.to_string(), (keyfile_name.to_string(), 0));

    let mut indexfile = IndexFile {
        default_index: 0,
        max_index: 0,
        default_keyfile_name: keyfile_name.to_string(),
        map_account_keyfile,
    };
    wallet_dir.insert_indexfile(&mut indexfile)
}

/// Increment max index in indexfile and set default the new one.
fn increment_indexfile(wallet_dir: &WalletDirectory, filename: &str, account_name: &str) -> Result<()> {
    let indexfile = wallet_dir.load_indexfile()?;
    let mut incremented_indexfile = indexfile.next_index(filename, account_name);
    wallet_dir.update_indexfile(&mut incremented_indexfile)
}

pub fn get_max_index(wallet_dir: &WalletDirectory) -> Result<u32> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.max_index)
}

pub fn get_default_index(wallet_dir: &WalletDirectory) -> Result<u32> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.default_index)
}

pub fn get_default_keyfile_name(wallet_dir: &WalletDirectory) -> Result<String> {
    let indexfile = wallet_dir.load_indexfile()?;
    Ok(indexfile.default_keyfile_name)
}

pub fn wallet_keystore_dirs(root_dir: &PathBuf) -> Result<(WalletDirectory, KeystoreDirectory)> {
    // configure wallet directory
    let wallet_dir = WalletDirectory::create(&root_dir)?;

    // configure ketstore directory
    let keystore_dir_path = wallet_dir.get_default_keystore_dir();
    let keystore_dir = KeystoreDirectory::create(keystore_dir_path)?;

    Ok((wallet_dir, keystore_dir))
}
