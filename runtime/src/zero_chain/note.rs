extern crate substrate_primitives as primitives;
extern crate parity_crypto as crypto;
extern crate rust_crypto as rcrypto;
extern crate subtle;

use rand::OsRng;
use primitives::{hashing::blake2_256, ed25519::{Pair, Public, PKCS_LEN}};
use rcrypto::exchange;

pub use crypto::KEY_ITERATIONS;

pub type SecretKey = [u8; PKCS_LEN];
// pub type Publickey = primitives::H256;
pub type Publickey = Public;

/// convert Vec<u8> to array[u8; 32]
fn vec_as_u8_32_array(vector: Vec<u8>) -> [u8; 32] {
    let mut arr = [0u8; 32];
    for (place, element) in arr.iter_mut().zip(vector.iter()) {
        *place = *element;
    }
    arr
}

// TODO: change to blake2_256
/// Get keys for encrypt and mac through the key derivation function
fn concat_kdf(key_material: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    const SHA256BlockSize: usize = 64;
    const reps: usize = (32 + 7) * 8 / (SHA256BlockSize * 8);

    let mut buffers: Vec<u8> = Vec::new();
    for counter in 0..(reps+1) {
        let mut sha256 = Sha256::new();
        let mut tmp: Vec<u8> = Vec::new();
        tmp.write_u32::<BigEndian>((counter + 1) as u32).unwrap();
        sha256.input(&tmp);
        sha256.input(&key_material);
        buffers.append(&mut sha256.result().as_ref().into());
    }

    vec_as_u8_32_array(buffers).split_at(16)
    // [u8; 32]::from(&buffers[0..32])
}

pub struct Note {
    pub value: u64,
    pub public_key: Publickey,
    // pub E::Fs, // the commitment randomness
}

pub struct EncryptedNote {
    ciphertext: Vec<u8>,
    iv: [u8; 16],
    mac: [u8; 32],
    ephemeral_public: Public, 
}

impl EncryptedNote {
    pub fn new(value: u64, public_key: Publickey) -> Result<Self, ECIESError> {
        Ok(Note {
            value,
            public_key,
        })
    }

    // TODO: fix type of plain_note 
    /// Encrypt a Note with public key
    pub fn encrypt_note(&self, plain_note: &[u8; PKCS_LEN], public_key: Publickey) -> Self {
        let mut rng = OsRng::new().expect("OS Randomness available on all supported platforms; qed");
        let data: &str = &self.value.to_string();

        let ephemeral_secret: [u8; PKCS_LEN] = rng.gen();
        let pair = Pair::from_seed(&ephemeral_secret);
        let ephemeral_public = pair.public();
    
        // let salt: [u8; 32] = rng.gen();
        let shared_secret = exchange(&public_key.0, &ephemeral_secret);
        
		// [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]        
        let (derived_left_bits, derived_right_bits) = concat_kdf(shared_secret);            

        // an initialisation vector
        let iv: [u8; 16] = rng.gen();
        // let mut iv_encrypted = vec![0u8; 16 + data.len()];
        // iv_encrypted[0..16].copy_from_slice(iv.as_ref());

        let mut ciphertext = vec![0u8; PKCS_LEN];

        cryto::aes::encrypt_128_ctr(&derived_left_bits, &iv, plain_note, &mut *ciphertext)
            .expect("input lengths of key and iv are both 16; qed");
        
        // Blake2_256(DK[16..31] ++ <ciphertext>), where DK[16..31] - derived_right_bits
        let mac = blake2_256(&crypto::derive_mac(&derived_right_bits, &*ciphertext));

        EncryptedNote {
            ciphertext,
            iv,
            mac,
            ephemeral_public,
        }

    }

    /// Decrypt a Note with secret key
    pub fn decrypt_note(&self, secret_key: &SecretKey) -> Result<[u8; PKCS_LEN]> {
        let shared_secret = exhange(&self.ephemeral_public.0, secret_key);

        // [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]        
        let (derived_left_bits, derived_right_bits) = concat_kdf(shared_secret); 

        // Blake2_256(DK[16..31] ++ <ciphertext>), where DK[16..31] - derived_right_bits
        let mac = blake2_256(&crypto::derive_mac(&derived_right_bits, &*ciphertext));

        if subtle::slices_equal(&mac[..], &self.mac[..]) != 1 {
			return Err(ErrorKind::InvalidPassword.into());
		}

        let mut plain = [0; PKCS_LEN];
        crypto::aes::decrypt_128_ctr(&derived_left_bits, &self.iv, &self.ciphertext, &mut plain[..])
            .expect("input lengths of key and iv are both 16; qed");
        Ok(plain)
    }
}
