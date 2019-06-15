use crate::{ZPARAMS, PARAMS};
use crate::derive::EncryptionKeyBytes;
use keys;
use primitives::{hexdisplay::{HexDisplay, AsBytesRef}, crypto::{Ss58Codec, Derive, DeriveJunction}};
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr};
use pairing::bls12_381::Bls12;
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, fs::Fs as zFs, FixedGenerators as zFixedGenerators}
};
use proofs::{
    primitives::{EncryptionKey, bytes_to_uniform_fs},
};
use keys::EncryptionKey as zEncryptionKey;
use zprimitives::PkdAddress;
use zcrypto::elgamal as zelgamal;
use polkadot_rs::{Api, hexstr_to_vec};
use parity_codec::Encode;
use rand::{OsRng, Rng};
use hex;
use bip39::{Mnemonic, Language, MnemonicType};
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
        gen_from_seed(seed, None)
    }

    pub fn generate_from_seed(seed: [u8; 32]) -> Self {
        gen_from_seed(seed, None)
    }

    pub fn print_from_phrase(phrase: &str, password: Option<&str>) {
        let seed = mini_secret_from_entropy(
            Mnemonic::from_phrase(phrase, Language::English)
                .unwrap_or_else(|_|
                    panic!("Phrase is not a valid BIP-39 phrase: \n {}", phrase)
                ).entropy(),
            password.unwrap_or("")
        )
        .expect("32 bytes can always build a key; qed")
        .to_bytes();

        let print_keys = gen_from_seed(seed, Some(phrase));

        println!("Phrase `{}` is account:\n Seed: 0x{}\n Decryption key: 0x{}\n Encryption key (hex): 0x{}\n Address (SS58): {}",
            phrase,
            hex::encode(&print_keys.seed[..]),
            hex::encode(&print_keys.decryption_key[..]),
            hex::encode(&print_keys.encryption_key[..]),
            print_keys.ss58_encryption_key,
        );
    }
}

fn gen_from_seed(seed: [u8; 32], phrase: Option<&str>) -> PrintKeys {
    let pgk = keys::ProofGenerationKey::<zBls12>::from_seed(&seed[..], &ZPARAMS);
    let decryption_key = pgk.into_decryption_key();

    let mut dk_buf = [0u8; 32];
    decryption_key.0.into_repr().write_le(&mut &mut dk_buf[..]).unwrap();

    let encryption_key = pgk.into_encryption_key(&ZPARAMS);

    let mut ek_buf = [0u8; 32];
    encryption_key.write(&mut ek_buf[..]).expect("fails to write payment address");

    let ek_ss58 = EncryptionKeyBytes(ek_buf).to_ss58check();

    // let phrase = match phrase {
    //     Some(p) => p,
    //     None => None,
    // }

    PrintKeys {
        phrase: phrase.map(|e| e.to_string()),
        seed: seed,
        decryption_key: dk_buf,
        encryption_key: ek_buf,
        ss58_encryption_key: ek_ss58,
    }
}

pub fn seed_to_array(seed: &str) -> [u8; 32] {
    let vec = hex::decode(seed).unwrap();
    let mut array = [0u8; 32];
    let slice = &vec[..array.len()];
    array.copy_from_slice(slice);

    array
}

/// Get encrypted and decrypted balance for the decryption key
pub fn get_balance_from_decryption_key(mut decryption_key: &[u8], api: Api) -> (u32, Vec<u8>, String) {
    let p_g = zFixedGenerators::Diversifier; // 1

    let mut decryption_key_repr = zFs::default().into_repr();
    decryption_key_repr.read_le(&mut decryption_key).unwrap();
    let decryption_key_fs = zFs::from_repr(decryption_key_repr).unwrap();
    let decryption_key = keys::DecryptionKey(decryption_key_fs);

    let encryption_key = zEncryptionKey::from_decryption_key(&decryption_key, &ZPARAMS as &zJubjubBls12);
    let account_id = PkdAddress::from_encryption_key(&encryption_key);

    let mut encrypted_balance_str = api.get_storage(
        "ConfTransfer",
        "EncryptedBalance",
        Some(account_id.encode())
        ).unwrap();

    // TODO: remove unnecessary prefix
    for _ in 0..4 {
        encrypted_balance_str.remove(2);
    }

    let encrypted_balance = hexstr_to_vec(encrypted_balance_str.clone());
    let ciphertext = zelgamal::Ciphertext::<zBls12>::read(&mut &encrypted_balance[..], &ZPARAMS).expect("Invalid data");

    let decrypted_balance = ciphertext.decrypt(decryption_key, p_g, &ZPARAMS).unwrap();

    (decrypted_balance, encrypted_balance, encrypted_balance_str)
}

pub fn get_address(seed: &[u8]) -> Vec<u8> {
    let address = EncryptionKey::<Bls12>::from_seed(seed, &PARAMS);

    let mut address_bytes = vec![];
    address.write(&mut address_bytes).unwrap();
    address_bytes
}
