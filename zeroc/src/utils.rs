use crate::ZPARAMS;
use keys;
use primitives::crypto::{Ss58Codec, Drive, DeriveJunction};
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, fs::Fs as zFs, FixedGenerators as zFixedGenerators}
};
use keys::EncryptionKey as zEncryptionKey;
use zprimitives::PkdAddress;
use zcrypto::elgamal as zelgamal;
use polkadot_rs::{Api, hexstr_to_vec};
use parity_codec::Encode;
use rand::{OsRng, Rng};
use hex;

pub struct PrintKeys {
    pub seed: [u8; 32],
    pub decryption_key: [u8; 32],
    pub encryption_key: [u8; 32],
}

impl PrintKeys {
    pub fn generate() -> Self {
        let rng = &mut OsRng::new().expect("should be able to construct RNG");
        let seed: [u8; 32] = rng.gen();
        gen_seed(seed)
    }

    pub fn generate_from_seed(seed: [u8; 32]) -> Self {
        gen_seed(seed)
    }
}

fn gen_seed(seed: [u8; 32]) -> PrintKeys {
    let pgk = keys::ProofGenerationKey::<zBls12>::from_seed(&seed[..], &ZPARAMS);
    let decryption_key: zFs = pgk.bdk();

    let mut dk_buf = [0u8; 32];
    decryption_key.into_repr().write_le(&mut &mut dk_buf[..]).unwrap();

    let encryption_key = pgk.into_encryption_key(&ZPARAMS);

    let mut ek_buf = [0u8; 32];
    encryption_key.write(&mut ek_buf[..]).expect("fails to write payment address");

    PrintKeys {
        seed: seed,
        decryption_key: dk_buf,
        encryption_key: ek_buf,
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
    let decryption_key = zFs::from_repr(decryption_key_repr).unwrap();

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
