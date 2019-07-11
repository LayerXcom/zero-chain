use proofs::PARAMS;
use zprimitives::PARAMS as ZPARAMS;
use crate::ss58::EncryptionKeyBytes;
use keys;
use primitives::crypto::Ss58Codec;
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr, io};
use pairing::bls12_381::Bls12;
use zjubjub::curve::FixedGenerators as zFixedGenerators;
use proofs::{EncryptionKey, DecryptionKey};
use keys::EncryptionKey as zEncryptionKey;
use zprimitives::PkdAddress;
use zcrypto::elgamal as zelgamal;
use polkadot_rs::{Api, hexstr_to_vec};
use parity_codec::Encode;
use rand::{OsRng, Rng};
use hex;
use bip39::{Mnemonic, Language};
use substrate_bip39::mini_secret_from_entropy;

pub struct PrintKeys {
    pub phrase: Option<String>,
    pub seed: [u8; 32],
    pub decryption_key: [u8; 32],
    pub encryption_key: [u8; 32],
    pub ss58_encryption_key: String,
}

impl PrintKeys {
    pub fn generate() -> Self {
        let rng = &mut OsRng::new().expect("should be able to construct RNG");
        let seed: [u8; 32] = rng.gen();
        gen_from_seed(seed, None).unwrap()
    }

    pub fn generate_from_seed(seed: [u8; 32]) -> Self {
        gen_from_seed(seed, None).unwrap()
    }

    pub fn print_from_phrase(phrase: &str, password: Option<&str>, lang: Language) {
        let seed = phrase_to_seed(phrase, password, lang);
        let print_keys = gen_from_seed(seed, Some(phrase)).unwrap();

        println!("Phrase `{}` is account:\n Seed: 0x{}\n Decryption key: 0x{}\n Encryption key (hex): 0x{}\n Address (SS58): {}",
            phrase,
            hex::encode(&print_keys.seed[..]),
            hex::encode(&print_keys.decryption_key[..]),
            hex::encode(&print_keys.encryption_key[..]),
            print_keys.ss58_encryption_key,
        );
    }
}

pub fn phrase_to_seed(phrase: &str, password: Option<&str>, lang: Language) -> [u8; 32] {
    mini_secret_from_entropy(
        Mnemonic::from_phrase(phrase, lang)
            .unwrap_or_else(|_|
                panic!("Phrase is not a valid BIP-39 phrase: \n {}", phrase)
            ).entropy(),
        password.unwrap_or("")
    )
    .expect("32 bytes can always build a key; qed")
    .to_bytes()
}

fn gen_from_seed(seed: [u8; 32], phrase: Option<&str>) -> io::Result<PrintKeys> {
    let pgk = keys::ProofGenerationKey::<zBls12>::from_seed(&seed[..], &ZPARAMS);
    let decryption_key = pgk.into_decryption_key()?;

    let mut dk_buf = [0u8; 32];
    decryption_key.0.into_repr().write_le(&mut &mut dk_buf[..])?;

    let encryption_key = pgk.into_encryption_key(&ZPARAMS)?;

    let mut ek_buf = [0u8; 32];
    encryption_key.write(&mut ek_buf[..])?;

    let ek_ss58 = EncryptionKeyBytes(ek_buf).to_ss58check();

    Ok(PrintKeys {
        phrase: phrase.map(|e| e.to_string()),
        seed: seed,
        decryption_key: dk_buf,
        encryption_key: ek_buf,
        ss58_encryption_key: ek_ss58,
    })
}

pub fn seed_to_array(seed: &str) -> [u8; 32] {
    let vec = hex::decode(seed).unwrap();
    let mut array = [0u8; 32];
    let slice = &vec[..array.len()];
    array.copy_from_slice(slice);

    array
}

fn no_std(dec_key: &DecryptionKey<Bls12>) -> keys::DecryptionKey<zBls12> {
    let mut dec_key_vec = vec![];
    dec_key.write(&mut dec_key_vec).unwrap();
    keys::DecryptionKey::read(&mut &dec_key_vec[..]).unwrap()
}

pub struct BalanceQuery {
    pub decrypted_balance: u32,
    pub encrypted_balance: Vec<u8>, // total of encrypted balance and pending transfer
    pub encrypted_balance_str: String,
    pub pending_transfer_str: String,
}

// Temporary code.
impl BalanceQuery {
    /// Get encrypted and decrypted balance for the decryption key
    pub fn get_balance_from_decryption_key(dec_key: &DecryptionKey<Bls12>, api: Api) -> Self {
        let p_g = zFixedGenerators::Diversifier; // 1

        let encryption_key = zEncryptionKey::from_decryption_key(&no_std(&dec_key), &*ZPARAMS);
        let account_id = PkdAddress::from_encryption_key(&encryption_key);

        let mut encrypted_balance_str = api.get_storage(
            "EncryptedBalances",
            "EncryptedBalance",
            Some(account_id.encode())
            ).unwrap();

        let mut pending_transfer_str = api.get_storage(
            "EncryptedBalances",
            "PendingTransfer",
            Some(account_id.encode())
        ).unwrap();


        let decrypted_balance;
        let p_decrypted_balance;
        let mut ciphertext = None;
        let mut p_ciphertext = None;

        // TODO: redundant code
        if encrypted_balance_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                encrypted_balance_str.remove(2);
            }

            let encrypted_balance = hexstr_to_vec(encrypted_balance_str.clone());
            ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &encrypted_balance[..], &ZPARAMS).expect("Invalid data"));
            decrypted_balance = ciphertext.clone().unwrap().decrypt(&no_std(&dec_key), p_g, &ZPARAMS).unwrap();
        } else {
            decrypted_balance = 0;
        }

        if pending_transfer_str.as_str() != "0x00" {
            // TODO: remove unnecessary prefix. If it returns `0x00`, it will be panic.
            for _ in 0..4 {
                pending_transfer_str.remove(2);
            }

            let pending_transfer = hexstr_to_vec(pending_transfer_str.clone());
            p_ciphertext = Some(zelgamal::Ciphertext::<zBls12>::read(&mut &pending_transfer[..], &ZPARAMS).expect("Invalid data"));
            p_decrypted_balance = p_ciphertext.clone().unwrap().decrypt(&no_std(&dec_key), p_g, &ZPARAMS).unwrap();
        } else {
            p_decrypted_balance = 0;
        }

        let zero = zelgamal::Ciphertext::<zBls12>::zero();
        let enc_total = ciphertext.unwrap_or(zero.clone()).add(&p_ciphertext.unwrap_or(zero), &*ZPARAMS);
        let mut buf = vec![0u8; 64];
        enc_total.write(&mut buf[..]).unwrap();

        BalanceQuery {
            decrypted_balance: decrypted_balance + p_decrypted_balance,
            encrypted_balance: buf,
            encrypted_balance_str,
            pending_transfer_str,
        }
    }
}

pub fn get_address(seed: &[u8]) -> std::io::Result<Vec<u8>> {
    let address = EncryptionKey::<Bls12>::from_seed(seed, &PARAMS)?;

    let mut address_bytes = vec![];
    address.write(&mut address_bytes)?;

    Ok(address_bytes)
}
