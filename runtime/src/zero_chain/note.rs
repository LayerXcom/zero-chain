extern crate substrate_primitives as primitives;
extern crate parity_crypto as crypto;
extern crate crypto as rcrypto;
extern crate rand;
extern crate substrate_keystore;

use self::rand::{Rng, OsRng};
use primitives::{hashing::blake2_256, ed25519::{Pair, PKCS_LEN}};
use self::rcrypto::ed25519::exchange;
// use {untrusted, pkcs8, error, der};
// use failure::{Error, err_msg};

fn to_array(slice: &[u8]) -> [u8; 16] {
    let mut array = [0u8; 16];
    for (&x, p) in slice.iter().zip(array.iter_mut()) {
        *p = x;
    }
    array
}

// TODO: looping for hashes
/// Get keys for encrypt and mac through the key derivation function
fn concat_kdf(key_material: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    // const SHA256BlockSize: usize = 64;
    // const reps: usize = (32 + 7) * 8 / (SHA256BlockSize * 8);

    // let mut buffers: Vec<u8> = Vec::new();
    // for counter in 0..(reps+1) {
    //     let mut sha256 = Sha256::new();
    //     let mut tmp: Vec<u8> = Vec::new();
    //     tmp.write_u32::<BigEndian>((counter + 1) as u32).unwrap();
    //     sha256.input(&tmp);
    //     sha256.input(&key_material);
    //     buffers.append(&mut sha256.result().as_ref().into());
    // }

    let hash = blake2_256(&key_material);
    let (left_hash, right_hash) = hash.split_at(16);
    (to_array(left_hash), to_array(right_hash))    
}


// trait GetPrivateScalar {
//     fn get_private_scalar(&self) -> [u8; 32];
// }

// fn unwrap_pkcs8(version: pkcs8::Version, input: untrusted::Input)
//         -> Result<(untrusted::Input, Option<untrusted::Input>),
//                   error::Unspecified> {
//     let (private_key, public_key) =
//         pkcs8::unwrap_key(&PKCS8_TEMPLATE, version, input)?;
//     let private_key = private_key.read_all(error::Unspecified, |input| {
//         der::expect_tag_and_get_value(input, der::Tag::OctetString)
//     })?;
//     Ok((private_key, public_key))
// }

pub struct Note {
    pub value: u64,
    pub public_key: [u8; 32],
    // pub E::Fs, // the commitment randomness
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct EncryptedNote {
    ciphertext: Vec<u8>,
    iv: [u8; 16],
    mac: [u8; 32],
    ephemeral_public: [u8; 32], 
}

impl EncryptedNote {  
    // TODO: fix type of plain_note 
    /// Encrypt a Note with public key
    pub fn encrypt_note(plain_note: &[u8; PKCS_LEN], public_key: [u8; 32]) -> Self {
        let mut rng = OsRng::new().expect("OS Randomness available on all supported platforms; qed");        

        let ephemeral_private: [u8; 32] = rng.gen();       

        // Make a new key pair from a seed phrase.
	    // NOTE: prefer pkcs#8 unless security doesn't matter -- this is used primarily for tests. 
        // https://github.com/paritytech/substrate/issues/1063
        let pair = Pair::from_seed(&ephemeral_private);                    
        let ephemeral_public = pair.public().0;
            
        let shared_secret = exchange(&public_key, &ephemeral_private);
                
		// [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]        
        let (derived_left_bits, derived_right_bits) = concat_kdf(shared_secret);            

        // an initialisation vector
        let iv: [u8; 16] = rng.gen();                
        let mut ciphertext = vec![0u8; PKCS_LEN];

        crypto::aes::encrypt_128_ctr(&derived_left_bits, &iv, plain_note, &mut *ciphertext)
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

    /// Decrypt a Note with private key
    pub fn decrypt_note(&self, private_key: &[u8; 32]) -> [u8; PKCS_LEN] {
        let shared_secret = exchange(&self.ephemeral_public, private_key);

        // [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]        
        let (derived_left_bits, derived_right_bits) = concat_kdf(shared_secret); 

        // Blake2_256(DK[16..31] ++ <ciphertext>), where DK[16..31] - derived_right_bits
        let mac = blake2_256(&crypto::derive_mac(&derived_right_bits, &*self.ciphertext));

        // TODO: ref: https://github.com/rust-lang/rust/issues/16913
        if !(&mac[..] == &self.mac[..]) {
            // TODO: elaborate error handling
			panic!("Not match macs");
		}

        let mut plain = [0; PKCS_LEN];
        crypto::aes::decrypt_128_ctr(&derived_left_bits, &self.iv, &self.ciphertext, &mut plain[..])
            .expect("input lengths of key and iv are both 16; qed");
        plain
    }
}

#[cfg(test)]
    use super::*;

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng = OsRng::new().expect("OS Randomness available on all supported platforms; qed");        
        let private_key: [u8; 32] = rng.gen(); 
        let pair = Pair::from_seed(&private_key);                    
        let public_key = pair.public();

        let plain_note = [1; PKCS_LEN];

        let encrypted_note = EncryptedNote::encrypt_note(&plain_note, public_key.0);
        let decrypt_note = encrypted_note.decrypt_note(&private_key);

        assert_eq!(&plain_note[..], &decrypt_note[..]);
    }

    #[test]
    #[should_panic]
    fn decrypt_wrong_private_key() {
        let mut rng = OsRng::new().expect("OS Randomness available on all supported platforms; qed");        
        let private_key: [u8; 32] = rng.gen(); 
        let pair = Pair::from_seed(&private_key);                    
        let public_key = pair.public();

        let plain_note = [1; PKCS_LEN];

        let encrypted_note = EncryptedNote::encrypt_note(&plain_note, public_key.0);

        let wrong_private_key = [3; 32];
        let _ = encrypted_note.decrypt_note(&wrong_private_key);        
    }