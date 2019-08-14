
use zprimitives::PARAMS as ZPARAMS;
use crate::ss58::EncryptionKeyBytes;
use primitives::crypto::Ss58Codec;
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr, io};
use rand::{OsRng, Rng};
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
