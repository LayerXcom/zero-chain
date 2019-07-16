use std::path::{PathBuf, Path};
use std::io::{BufReader, Read};
use std::fs::File;
use rand::{Rng, Rand};
use proofs::{SpendingKey, Transaction, ProofGenerationKey, EncryptionKey, PARAMS, elgamal};
use pairing::{bls12_381::Bls12, Field};
use super::constants::*;
use crate::term::Term;
use crate::wallet::{Result, DirOperations};
use crate::wallet::commands::{wallet_keystore_dirs, get_default_keyfile_name};
use crate::utils::print_keys::BalanceQuery; // TODO

use zjubjub::{
    curve::{fs::Fs as zFs, FixedGenerators as zFixedGenerators},
    redjubjub::PrivateKey as zPrivateKey
    };
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr};
use zprimitives::{PARAMS as ZPARAMS, Proof, Ciphertext as zCiphertext, PkdAddress, SigVerificationKey, RedjubjubSignature, SigVk};
use zerochain_runtime::{UncheckedExtrinsic, Call, EncryptedBalancesCall, EncryptedAssetsCall};
use runtime_primitives::generic::Era;
use parity_codec::{Compact, Encode, Decode};
use primitives::blake2_256;
use polkadot_rs::{Api, Url, hexstr_to_u64};
use scrypto::jubjub::{fs::Fs, FixedGenerators};
use bellman::groth16::{Parameters, PreparedVerifyingKey};

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

    // Get setuped parameters to compute zk proving.
    let proving_key = get_pk(PROVING_KEY_PATH)?;
    let prepared_vk = get_vk(VERIFICATION_KEY_PATH)?;

    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let issuer_address = EncryptionKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)?;

    let enc_amount = elgamal::Ciphertext::encrypt(amount, Fs::rand(rng), &issuer_address, p_g, &PARAMS);

    // let zero = elgamal::Ciphertext::zero();

    println!("Computing zk proof...");
    let tx = Transaction::gen_tx(
        amount,
        0, // dummy value for remaining balance
        &proving_key,
        &prepared_vk,
        &issuer_address,
        &spending_key,
        enc_amount,
        rng,
        0
        )
    .expect("fails to generate the tx");

    println!("Start submitting a transaction to Zerochain...");
    subscribe_event(api.clone(), amount);
    submit_asset_issue(&tx, &api, rng);

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

    // Get setuped parameters to compute zk proving.
    let proving_key = get_pk(PROVING_KEY_PATH)?;
    let prepared_vk = get_vk(VERIFICATION_KEY_PATH)?;

    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;

    // Get set fee amount as `TransactionBaseFee` in encrypyed-balances module.
    let fee_str = api.get_storage("EncryptedAssets", "TransactionBaseFee", Some(asset_id.encode()))
        .expect("should be fetched TransactionBaseFee from ConfTransfer module of Zerochain.");
    let fee = hexstr_to_u64(fee_str) as u32;

    let balance_query = BalanceQuery::get_encrypted_asset(asset_id, &dec_key, api.clone());
    let remaining_balance = balance_query.decrypted_balance - amount - fee;
    assert!(balance_query.decrypted_balance >= amount + fee, "Not enough balance you have");

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)?;
    let encrypted_balance = elgamal::Ciphertext::read(&mut &balance_query.encrypted_balance[..], &*PARAMS)?;

    println!("Computing zk proof...");
    let tx = Transaction::gen_tx(
        amount,
        remaining_balance,
        &proving_key,
        &prepared_vk,
        &recipient_account_id,
        &spending_key,
        encrypted_balance,
        rng,
        fee
        )
    .expect("fails to generate the tx");

    println!("Start submitting a transaction to Zerochain...");
    subscribe_event(api.clone(), remaining_balance);
    submit_asset_transfer(asset_id, &tx, &api, rng);

    Ok(())
}

pub fn transfer_tx<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term)?;

    println!("Preparing paramters...");

    let api = Api::init(url);

    // Get setuped parameters to compute zk proving.
    let proving_key = get_pk(PROVING_KEY_PATH)?;
    let prepared_vk = get_vk(VERIFICATION_KEY_PATH)?;

    let spending_key = spending_key_from_keystore(root_dir, &password[..])?;
    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()?;

    // Get set fee amount as `TransactionBaseFee` in encrypyed-balances module.
    let fee_str = api.get_storage("EncryptedBalances", "TransactionBaseFee", None)
        .expect("should be fetched TransactionBaseFee from ConfTransfer module of Zerochain.");
    let fee = hexstr_to_u64(fee_str) as u32;

    let balance_query = BalanceQuery::get_encrypted_balance(&dec_key, api.clone());
    let remaining_balance = balance_query.decrypted_balance - amount - fee;
    assert!(balance_query.decrypted_balance >= amount + fee, "Not enough balance you have");

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)?;
    let encrypted_balance = elgamal::Ciphertext::read(&mut &balance_query.encrypted_balance[..], &*PARAMS)?;

    println!("Computing zk proof...");
    let tx = Transaction::gen_tx(
        amount,
        remaining_balance,
        &proving_key,
        &prepared_vk,
        &recipient_account_id,
        &spending_key,
        encrypted_balance,
        rng,
        fee
        )
    .expect("fails to generate the tx");

    println!("Start submitting a transaction to Zerochain...");
    subscribe_event(api.clone(), remaining_balance);
    submit_confidential_transfer(&tx, &api, rng);

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

pub fn get_pk(path: &str) -> Result<Parameters::<Bls12>> {
    let buf_pk = read_zk_params_with_path(path)?;
    let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true)?;

    Ok(proving_key)
}

pub fn get_vk(path: &str) -> Result<PreparedVerifyingKey::<Bls12>> {
    let buf_vk = read_zk_params_with_path(path)?;
    let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..])?;

    Ok(prepared_vk)
}

fn read_zk_params_with_path(path: &str) -> Result<Vec<u8>> {
    let params_path = Path::new(path);
    let file = File::open(&params_path)?;

    let mut params_reader = BufReader::new(file);
    let mut params_buf = vec![];
    params_reader.read_to_end(&mut params_buf)?;

    Ok(params_buf)
}

pub fn submit_confidential_transfer<R: Rng>(tx: &Transaction, api: &Api, rng: &mut R) {
    let calls = Call::EncryptedBalances(EncryptedBalancesCall::confidential_transfer(
        Proof::from_slice(&tx.proof[..]),
        PkdAddress::from_slice(&tx.address_sender[..]),
        PkdAddress::from_slice(&tx.address_recipient[..]),
        zCiphertext::from_slice(&tx.enc_amount_sender[..]),
        zCiphertext::from_slice(&tx.enc_amount_recipient[..]),
        zCiphertext::from_slice(&tx.enc_fee[..]),
    ));

    submit_tx(calls, tx, api, rng);
}

pub fn submit_asset_issue<R: Rng>(tx: &Transaction, api: &Api, rng: &mut R) {
    let calls = Call::EncryptedAssets(EncryptedAssetsCall::issue(
        Proof::from_slice(&tx.proof[..]),
        PkdAddress::from_slice(&tx.address_recipient[..]),
        zCiphertext::from_slice(&tx.enc_amount_recipient[..]),
        zCiphertext::from_slice(&tx.enc_fee[..]),
        zCiphertext::from_slice(&tx.enc_balance[..])
    ));

    submit_tx(calls, tx, api, rng);
}

pub fn submit_asset_transfer<R: Rng>(asset_id: u32, tx: &Transaction, api: &Api, rng: &mut R) {
    let calls = Call::EncryptedAssets(EncryptedAssetsCall::confidential_transfer(
        asset_id,
        Proof::from_slice(&tx.proof[..]),
        PkdAddress::from_slice(&tx.address_sender[..]),
        PkdAddress::from_slice(&tx.address_recipient[..]),
        zCiphertext::from_slice(&tx.enc_amount_sender[..]),
        zCiphertext::from_slice(&tx.enc_amount_recipient[..]),
        zCiphertext::from_slice(&tx.enc_fee[..]),
    ));

    submit_tx(calls, tx, api, rng);
}

fn submit_tx<R: Rng>(calls: Call, tx: &Transaction, api: &Api, rng: &mut R) {
    let p_g = zFixedGenerators::Diversifier; // 1

    let mut rsk_repr = zFs::default().into_repr();
    rsk_repr.read_le(&mut &tx.rsk[..])
        .expect("should be casted to Fs's repr type.");
    let rsk = zFs::from_repr(rsk_repr)
        .expect("should be casted to Fs type from repr type.");

    let sig_sk = zPrivateKey::<zBls12>(rsk);
    let sig_vk = SigVerificationKey::from_slice(&tx.rvk[..]);

    let era = Era::Immortal;
    let index = api.get_nonce(&sig_vk).expect("Nonce must be got.");
    let checkpoint = api.get_genesis_blockhash()
        .expect("should be fetched the genesis block hash from zerochain node.");

    let raw_payload = (Compact(index), calls, era, checkpoint);

    let sig = raw_payload.using_encoded(|payload| {
        let msg = blake2_256(payload);
        let sig = sig_sk.sign(&msg[..], rng, p_g, &*ZPARAMS);

        let sig_vk = sig_vk.into_verification_key()
            .expect("should be casted to redjubjub::PublicKey<Bls12> type.");
        assert!(sig_vk.verify(&msg, &sig, p_g, &*ZPARAMS));

        sig
    });

    let sig_repr = RedjubjubSignature::from_signature(&sig);
    let uxt = UncheckedExtrinsic::new_signed(index, raw_payload.1, sig_vk.into(), sig_repr, era);
    let _tx_hash = api.submit_extrinsic(&uxt)
        .expect("Faild to submit a extrinsic to zerochain node.");
}

pub fn subscribe_event(api: Api, remaining_balance: u32) {
    use std::sync::mpsc::channel;
    use std::thread;
    use polkadot_rs::hexstr_to_vec;
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
                                            _address_sender, _address_recipient,
                                            _amount_sender, _amount_recipient,
                                            _fee_sender, _enc_balances, _sig_vk
                                        ) => println!("Submitting transaction is completed successfully. \n Remaining balance is {}", remaining_balance),
                                        encrypted_balances::RawEvent::InvalidZkProof() => {
                                            println!("Invalid zk proof.");
                                        }
                                    }
                                },
                                Event::encrypted_assets(enc_assets) => {
                                    match &enc_assets {
                                        encrypted_assets::RawEvent::Issued(
                                            _asset_id, _address, _total
                                        ) => println!("Submitting transaction is completed successfully. \n The total issued coin is {}", remaining_balance),
                                        encrypted_assets::RawEvent::ConfidentialAssetTransferred(
                                            _asset_id, _zkproof,
                                            _address_sender, _address_recipient,
                                            _amount_sender, _amount_recipient,
                                            _fee_sender, _enc_balances, _sig_vk
                                        ) => println!("Submitting transaction is completed successfully. \n Remaining balance is {}", remaining_balance),
                                        encrypted_assets::RawEvent::Destroyed(_asset_id, _address, _balance)
                                            => println!("destroyed coins."),
                                        encrypted_assets::RawEvent::InvalidZkProof() => println!("Invalid zk proof."),
                                    }
                                },
                                _ => /* warn!("ignoring unsupported module event: {:?}", event.event) */ {},
                            }
                        }
                    },
                    None => error!("couldn't decode event record list")
                }
            }
        });
}
