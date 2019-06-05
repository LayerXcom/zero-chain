use crate::ZPARAMS;
use keys;
use zpairing::{bls12_381::Bls12 as zBls12, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, fs::Fs as zFs}
};
use rand::{OsRng, Rng};

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
