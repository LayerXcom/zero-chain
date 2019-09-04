use std::path::PathBuf;
use rand::{Rng, Rand};
use proofs::{
    SpendingKey, ProofGenerationKey, EncryptionKey, PARAMS, elgamal,
    crypto_components::{MultiEncKeys, Confidential, Anonymous},
    crypto_components::{ProofBuilder, KeyContext, Calls, Submitter},
    constants::ANONIMITY_SIZE,
};
use pairing::bls12_381::Bls12;
use parity_codec::Decode;
use polkadot_rs::{Api, Url, hexstr_to_vec};
use scrypto::jubjub::{fs::Fs, FixedGenerators};
use super::constants::*;
use crate::error::Result;
use crate::term::Term;
use crate::wallet::DirOperations;
use crate::wallet::commands::{wallet_keystore_dirs, get_default_keyfile_name};
use crate::getter::{self, BalanceQuery};

pub fn asset_issue_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term).expect("Invalid password");
    println!("Preparing paramters...");

    let api = Api::init(url);
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1

    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let issuer_address = EncryptionKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)?;

    let enc_amount = vec![elgamal::Ciphertext::encrypt(amount, &Fs::rand(rng), &issuer_address, p_g, &PARAMS)];
    let multi_keys = MultiEncKeys::<Bls12, Confidential>::new(issuer_address.clone());

    println!("Computing zk proof...");
    subscribe_event(api.clone(), amount);

    println!("Start submitting a transaction to Zerochain...");
    KeyContext::read_from_path(CONF_PK_PATH, CONF_VK_PATH)?
        .gen_proof(
            amount,
            0,0,0,0,
            &spending_key,
            multi_keys,
            &enc_amount,
            getter::g_epoch(&api)?,
            rng,
            &PARAMS
        )?
        .submit(
            Calls::AssetIssue,
            &api,
            rng
        );

    Ok(())
}

pub fn asset_transfer_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    recipient_enc_key: &[u8],
    amount: u32,
    asset_id: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term)?;

    println!("Preparing paramters...");

    let api = Api::init(url);
    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;
    let fee = getter::fee(&api)?;

    let balance_query = BalanceQuery::get_encrypted_asset(asset_id, &dec_key, api.clone())?;
    let remaining_balance = balance_query.decrypted_balance - amount - fee;
    assert!(balance_query.decrypted_balance >= amount + fee, "Not enough balance you have");

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)?;
    let enc_balance = vec![elgamal::Ciphertext::read(&mut &balance_query.encrypted_balance[..], &*PARAMS)?];
    let multi_keys = MultiEncKeys::<Bls12, Confidential>::new(recipient_account_id.clone());

    println!("Computing zk proof...");
    if recipient_account_id == EncryptionKey::from_decryption_key(&dec_key, &*PARAMS) {
        subscribe_event(api.clone(), remaining_balance + amount);
    } else {
        subscribe_event(api.clone(), remaining_balance);
    }

    println!("Start submitting a transaction to Zerochain...");
    KeyContext::read_from_path(CONF_PK_PATH, CONF_VK_PATH)?
        .gen_proof(
            amount,
            fee,
            remaining_balance,
            0,
            0,
            &spending_key,
            multi_keys,
            &enc_balance,
            getter::g_epoch(&api)?,
            rng,
            &PARAMS
        )?
        .submit(
            Calls::AssetTransfer(asset_id),
            &api,
            rng
        );

    Ok(())
}

pub fn asset_burn_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    asset_id: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term).expect("Invalid password");
    println!("Preparing paramters...");

    let api = Api::init(url);
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1

    // Validate the asset balance
    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;
    let balance_query = BalanceQuery::get_encrypted_asset(asset_id, &dec_key, api.clone())?;
    assert!(balance_query.decrypted_balance != 0, "You don't have the asset. Asset id may be incorrect.");

    let amount = 0;
    let issuer_address = EncryptionKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)?;
    let enc_amount =  vec![elgamal::Ciphertext::encrypt(amount, &Fs::rand(rng), &issuer_address, p_g, &PARAMS)];
    let multi_keys = MultiEncKeys::<Bls12, Confidential>::new(issuer_address);

    println!("Computing zk proof...");
    subscribe_event(api.clone(), amount);

    println!("Start submitting a transaction to Zerochain...");
    KeyContext::read_from_path(CONF_PK_PATH, CONF_VK_PATH)?
        .gen_proof(
            amount,
            0, 0, 0, 0,
            &spending_key,
            multi_keys,
            &enc_amount,
            getter::g_epoch(&api)?,
            rng,
            &PARAMS
        )?
        .submit(
            Calls::AssetBurn(asset_id),
            &api,
            rng
        );

    Ok(())
}

pub fn confidential_transfer_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term)?;
    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;

    inner_confidential_transfer_tx(spending_key, recipient_enc_key, amount, url, rng)?;

    Ok(())
}

pub fn anonymous_transfer_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term)?;
    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;

    inner_anonymous_transfer_tx(spending_key, recipient_enc_key, amount, url, rng)?;

    Ok(())
}

pub fn transfer_tx_for_debug<R: Rng>(
    seed: &[u8],
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    let spending_key = SpendingKey::from_seed(seed);
    inner_confidential_transfer_tx(spending_key, recipient_enc_key, amount, url, rng)?;

    Ok(())
}

pub fn anonymous_transfer_tx_for_debug<R: Rng>(
    seed: &[u8],
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    let spending_key = SpendingKey::from_seed(seed);
    inner_anonymous_transfer_tx(spending_key, recipient_enc_key, amount, url, rng)?;

    Ok(())
}

fn inner_confidential_transfer_tx<R: Rng>(
    spending_key: SpendingKey::<Bls12>,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R
) -> Result<()> {
    println!("Preparing paramters...");

    let api = Api::init(url);
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;
    let fee = getter::fee(&api)?;

    let balance_query = BalanceQuery::get_encrypted_balance(&dec_key, api.clone())?;
    let remaining_balance = balance_query.decrypted_balance - amount - fee;
    assert!(balance_query.decrypted_balance >= amount + fee, "Not enough balance you have");

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)?;
    let multi_keys = MultiEncKeys::<Bls12, Confidential>::new(recipient_account_id.clone());
    let enc_balance = vec![elgamal::Ciphertext::read(&mut &balance_query.encrypted_balance[..], &*PARAMS)?];

    println!("Computing zk proof...");
    if recipient_account_id == EncryptionKey::from_decryption_key(&dec_key, &*PARAMS) {
        subscribe_event(api.clone(), remaining_balance + amount);
    } else {
        subscribe_event(api.clone(), remaining_balance);
    }

    println!("Start submitting a transaction to Zerochain...");
    KeyContext::read_from_path(CONF_PK_PATH, CONF_VK_PATH)?
        .gen_proof(
            amount,
            fee,
            remaining_balance,
            0,
            0,
            &spending_key,
            multi_keys,
            &enc_balance,
            getter::g_epoch(&api)?,
            rng,
            &PARAMS
        )?
        .submit(
            Calls::BalanceTransfer,
            &api,
            rng
        );

    Ok(())
}

fn inner_anonymous_transfer_tx<R: Rng>(
    spending_key: SpendingKey::<Bls12>,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R
) -> Result<()> {
    println!("Preparing paramters...");

    let api = Api::init(url);
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;
    let enc_key_sender = EncryptionKey::<Bls12>::from_decryption_key(&dec_key, &PARAMS);

    let balance_query = BalanceQuery::get_encrypted_balance(&dec_key, api.clone())?;
    let remaining_balance = balance_query.decrypted_balance - amount;
    assert!(balance_query.decrypted_balance >= amount, "Not enough balance you have");

    let s_index: usize = rng.gen_range(0, ANONIMITY_SIZE);
    let t_index: usize = rng.gen_range(0, ANONIMITY_SIZE);

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)?;
    let decoys = getter::get_enc_keys(&api, rng)?;
    let multi_keys = MultiEncKeys::<Bls12, Anonymous>::new(recipient_account_id.clone(), decoys.clone());

    let mut enc_keys = vec![];
    let mut j = 0;
    for i in 0..ANONIMITY_SIZE {
        if i == s_index {
            enc_keys.push(enc_key_sender.clone());
        } else if i == t_index {
            enc_keys.push(recipient_account_id.clone());
        } else {
            enc_keys.push(decoys[j].clone());
            j += 1;
        }
    }
    // TODO: sender and recpinent index should be configured here.
    enc_keys.push(enc_key_sender);
    enc_keys.push(recipient_account_id.clone());
    let enc_balances = getter::get_enc_balances(&api, &enc_keys[..])?;

    println!("Computing zk proof...");
    if recipient_account_id == EncryptionKey::from_decryption_key(&dec_key, &*PARAMS) {
        subscribe_event(api.clone(), remaining_balance + amount);
    } else {
        subscribe_event(api.clone(), remaining_balance);
    }

    println!("Start submitting a transaction to Zerochain...");
    KeyContext::read_from_path(ANONY_PK_PATH, ANONY_VK_PATH)?
        .gen_proof(
            amount,
            0,
            remaining_balance,
            s_index,
            t_index,
            &spending_key,
            multi_keys,
            &enc_balances[..],
            getter::g_epoch(&api)?,
            rng,
            &PARAMS
        )?
        .submit(
            Calls::AnonymousTransfer,
            &api,
            rng
        );

    Ok(())
}

pub fn spending_key_from_keystore(
    root_dir: PathBuf,
    password: &[u8],
) -> Result<SpendingKey<Bls12>>
{
    let (wallet_dir, keystore_dir) = wallet_keystore_dirs(&root_dir)?;

    let default_keyfile_name = get_default_keyfile_name(&wallet_dir)?;
    let keyfile = keystore_dir.load(&default_keyfile_name)?;

    let sk = keyfile.get_current_spending_key(password)?;

    Ok(sk)
}

pub fn prompt_password(term: &mut Term) -> Result<Vec<u8>> {
    // enter password
    term.info("Enter the wallet passowrd.\n")?;
    let password = term.passowrd("wallet password")?;
    Ok(password)
}

pub fn subscribe_event(api: Api, remaining_balance: u32) {
    use std::sync::mpsc::channel;
    use std::thread;
    use zerochain_runtime::Event;

    let (tx, rx) = channel();
    let _ = thread::Builder::new()
        .name("eventsubscriber".to_string())
        .spawn(move || {
            api.subscribe_events(tx.clone());
    });

    let _ = thread::Builder::new()
        .name("eventlistner".to_string())
        .spawn(move || {
            loop {
                let event_str = rx.recv().unwrap();
                let res_vec = hexstr_to_vec(event_str);
                let mut er_enc = res_vec.as_slice();
                let events = Vec::<system::EventRecord::<Event>>::decode(&mut er_enc);
                match events {
                    Some(events) => {
                        for event in &events {
                            match &event.event {
                                Event::encrypted_balances(enc_be) => {
                                    match &enc_be {
                                        encrypted_balances::RawEvent::ConfidentialTransfer(
                                            _zkproof,
                                            _enc_key_sender, _enc_key_recipient,
                                            _amount_sender, _amount_recipient,
                                            _fee_sender,  _randomness, _enc_balances, _sig_vk
                                        ) => println!("Submitting transaction is completed successfully. \n Remaining balance is {}", remaining_balance),
                                        encrypted_balances::RawEvent::InvalidZkProof() => {
                                            println!("Invalid zk proof.");
                                        }
                                    }
                                },
                                Event::encrypted_assets(enc_assets) => {
                                    match &enc_assets {
                                        encrypted_assets::RawEvent::Issued(
                                            asset_id, _address, _total
                                        ) => println!("Submitting transaction is completed successfully. \nThe total issued coin is {}. \nThe asset id is {}.", remaining_balance, asset_id),
                                        encrypted_assets::RawEvent::ConfidentialAssetTransferred(
                                            asset_id, _zkproof,
                                            _enc_key_sender, _enc_key_recipient,
                                            _amount_sender, _amount_recipient,
                                            _fee_sender, _randomness, _enc_balances, _sig_vk
                                        ) => println!("Submitting transaction is completed successfully. \nRemaining balance is {}. \nThe asset id is {}.", remaining_balance, asset_id),
                                        encrypted_assets::RawEvent::Destroyed(asset_id, _address, _balance, _pending_transfer)
                                            => println!("destroyed coins. \nThe asset id is {}.", asset_id),
                                        encrypted_assets::RawEvent::InvalidZkProof() => println!("Invalid zk proof."),
                                    }
                                },
                                // Event::anonymous_balances(enc_be) => {
                                //     match &enc_be {
                                //         // anonymous_balances::RawEvent::AnonymousTransfer(

                                //         // ) => ("Submitting transaction is completed successfully. \n Remaining balance is {}", remaining_balance),
                                //         anonymous_balances::RawEvent::InvalidZkProof() => {
                                //             println!("Invalid zk proof.");
                                //         }
                                //     }
                                // }
                                _ => /* warn!("ignoring unsupported module event: {:?}", event.event) */ {},
                            }
                        }
                    },
                    None => error!("couldn't decode event record list")
                }
            }
        });
}
