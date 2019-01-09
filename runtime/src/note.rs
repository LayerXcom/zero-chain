extern crate substrate_primitives as primitives;
use rand::OsRng;
use primitives::{hashing::blake2_256, ed25519::{Pair, Public, PKCS_LEN}};

pub type SecretKey = [u8; PKCS_LEN];
// pub type Publickey = primitives::H256;
pub type Publickey = Public;

pub struct Note {
    pub value: u64,
    pub public_key: Publickey,
    // pub E::Fs, // the commitment randomness
}

impl Note {
    pub fn new(value: u64, public_key: Publickey) -> Result<Self, ECIESError> {
        Ok(Note {
            value,
            public_key,
        })
    }

    /// Encrypt a Note with public key
    pub fn encrypt_note(&self) -> Result<Vec<u8>, ECIESError> {
        let mut rng = OsRng::new().expect("OS Randomness available on all supported platforms; qed");
        let data: &str = &self.value.to_string();

        let ephemeral_secret: [u8; PKCS_LEN] = rng.gen();
        let pair = Pair::from_seed(&ephemeral_secret);
        let ephemeral_public = pair.public();

        // an initialisation vector
        let iv: [u8; 16] = rng.gen();
        let mut iv_encrypted = vec![0u8; 16 + data.len()];
        iv_encrypted[0..16].copy_from_slice(iv.as_ref());

        let tag = 
        

        let mut ret = vec![0u8; 65 + 16 + data.len() + 32];

    }

    /// Decrypt a Note with secret key
    pub fn decrypt_note(&self, secret_key: &SecretKey,)
}
