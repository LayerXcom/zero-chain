use std::path::{PathBuf, Path};
use std::io::{BufReader, Read};
use std::fs::File;
use rand::Rng;
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
use zprimitives::{PARAMS as ZPARAMS, Proof, Ciphertext as zCiphertext, PkdAddress, SigVerificationKey, RedjubjubSignature};
use zerochain_runtime::{UncheckedExtrinsic, Call, ConfTransferCall};
use runtime_primitives::generic::Era;
use parity_codec::{Compact, Encode};
use primitives::blake2_256;
use polkadot_rs::{Api, Url, hexstr_to_u64};
use scrypto::jubjub::fs;
use bellman::groth16::{Parameters, PreparedVerifyingKey};

pub fn send_tx_with_arg<R: Rng>(
    term: &mut Term,
    root_dir: PathBuf,
    recipient_enc_key: &[u8],
    amount: u32,
    url: Url,
    rng: &mut R,
) -> Result<()> {
    // user can enter password first.
    let password = prompt_password(term).expect("Invalid password");

    println!("Preparing paramters...");

    let api = Api::init(url);
    // let alpha = fs::Fs::rand(rng);
    let alpha = fs::Fs::zero(); // TODO

    let buf_pk = read_zk_params_with_path(PROVING_KEY_PATH);
    let buf_vk = read_zk_params_with_path(VERIFICATION_KEY_PATH);

    let proving_key = Parameters::<Bls12>::read(&mut &buf_pk[..], true)
        .expect("should be casted to Parameters<Bls12> type.");
    let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..])
        .expect("should ne casted to PreparedVerifyingKey<Bls12> type");

    let fee_str = api.get_storage("ConfTransfer", "TransactionBaseFee", None)
        .expect("should be fetched TransactionBaseFee from ConfTransfer module of Zerochain.");
    let fee = hexstr_to_u64(fee_str) as u32;

    let spending_key = spending_key_from_keystore(root_dir, &password[..])
        .expect("should load from keystore.");

    let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&spending_key, &PARAMS)
        .into_decryption_key()
        .expect("should be generated decryption key from seed.");

    let balance_query = BalanceQuery::get_balance_from_decryption_key(&dec_key, api.clone());
    let remaining_balance = balance_query.decrypted_balance - amount - fee;
    assert!(balance_query.decrypted_balance >= amount + fee, "Not enough balance you have");

    let recipient_account_id = EncryptionKey::<Bls12>::read(&mut &recipient_enc_key[..], &PARAMS)
        .expect("should be casted to EncryptionKey<Bls12> type.");

    let encrypted_balance = elgamal::Ciphertext::read(&mut &balance_query.encrypted_balance[..], &*PARAMS)
        .expect("should be casted to Ciphertext type.");

    println!("Computing zk proof...");
    let tx = Transaction::gen_tx(
        amount,
        remaining_balance,
        alpha,
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
    submit_tx(&tx, &api, rng);
    println!("Remaining balance is {}", remaining_balance);

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

pub fn read_zk_params_with_path(path: &str) -> Vec<u8> {
    let params_path = Path::new(path);
    let file = File::open(&params_path)
        .expect(&format!("couldn't open {}", params_path.display()));

    let mut params_reader = BufReader::new(file);
    let mut params_buf = vec![];
    params_reader.read_to_end(&mut params_buf)
        .expect(&format!("couldn't read {}", params_path.display()));

    params_buf
}

pub fn submit_tx<R: Rng>(tx: &Transaction, api: &Api, rng: &mut R) {
    let p_g = zFixedGenerators::Diversifier; // 1

    let mut rsk_repr = zFs::default().into_repr();
    rsk_repr.read_le(&mut &tx.rsk[..])
        .expect("should be casted to Fs's repr type.");
    let rsk = zFs::from_repr(rsk_repr)
        .expect("should be casted to Fs type from repr type.");

    let sig_sk = zPrivateKey::<zBls12>(rsk);
    let sig_vk = SigVerificationKey::from_slice(&tx.rvk[..]);

    let calls = Call::ConfTransfer(ConfTransferCall::confidential_transfer(
        Proof::from_slice(&tx.proof[..]),
        PkdAddress::from_slice(&tx.address_sender[..]),
        PkdAddress::from_slice(&tx.address_recipient[..]),
        zCiphertext::from_slice(&tx.enc_amount_sender[..]),
        zCiphertext::from_slice(&tx.enc_amount_recipient[..]),
        sig_vk,
        zCiphertext::from_slice(&tx.enc_fee[..]),
    ));

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
