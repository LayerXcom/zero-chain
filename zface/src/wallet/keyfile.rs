//! Keyfile operations such as encryption/decryotion, sign.

use super::SerdeBytes;
use crate::derive::{ChildIndex, Derivation, ExtendedSpendingKey};
use crate::error::{KeystoreError, Result};
use crypto::Keccak256;
use pairing::bls12_381::Bls12;
use parity_crypto as crypto;
use proofs::{DecryptionKey, ProofGenerationKey, SpendingKey, PARAMS};
use rand::Rng;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    /// Unique Keyfile name which is used for filename.
    /// If this keyfile is not stored yet, no name exits.
    pub file_name: Option<String>,

    /// User defined account name
    pub account_name: String,

    /// SS58 format address
    pub ss58_address: String,

    /// Keyfile version
    pub version: u32,

    /// Encrypted private key
    pub encrypted_key: KeyCiphertext,
}

impl KeyFile {
    pub fn new<R: Rng>(
        account_name: &str,
        version: u32,
        password: &[u8],
        iters: u32,
        xsk: &ExtendedSpendingKey,
        rng: &mut R,
    ) -> Result<Self> {
        let encrypted_key = KeyCiphertext::encrypt(xsk, password, iters, rng)?;
        let ss58_address = xsk.try_into()?;

        Ok(KeyFile {
            file_name: None,
            account_name: account_name.to_string(),
            ss58_address,
            version,
            encrypted_key,
        })
    }

    pub fn create_master<R: Rng>(
        account_name: &str,
        version: u32,
        password: &[u8],
        iters: u32,
        rng: &mut R,
        seed: &[u8],
    ) -> Result<Self> {
        let xsk_master = ExtendedSpendingKey::master(seed);

        let encrypted_key = KeyCiphertext::encrypt(&xsk_master, password, iters, rng)?;
        let ss58_master_addr = (&xsk_master).try_into()?;

        Ok(KeyFile {
            file_name: None,
            account_name: account_name.to_string(),
            ss58_address: ss58_master_addr,
            version,
            encrypted_key,
        })
    }

    pub fn get_child_xsk(&self, password: &[u8], index: ChildIndex) -> Result<ExtendedSpendingKey> {
        let xsk = self.encrypted_key.decrypt(password)?;
        let xsk_child = xsk.derive_child(index)?;

        Ok(xsk_child)
    }

    pub fn get_current_spending_key(&self, password: &[u8]) -> Result<SpendingKey<Bls12>> {
        let xsk = self.encrypted_key.decrypt(password)?;
        Ok(xsk.spending_key)
    }

    pub fn get_dec_key(&self, password: &[u8]) -> Result<DecryptionKey<Bls12>> {
        let xsk = self.encrypted_key.decrypt(password)?;
        let dec_key = ProofGenerationKey::<Bls12>::from_spending_key(&xsk.spending_key, &*PARAMS)
            .into_decryption_key()?;

        Ok(dec_key)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeyCiphertext {
    pub ciphertext: SerdeBytes,
    pub mac: SerdeBytes,
    pub salt: SerdeBytes,
    pub iv: SerdeBytes,
    pub iters: u32,
}

impl KeyCiphertext {
    /// Encrypt plain bytes data
    /// Currently using `parity-crypto`.
    pub fn encrypt<R: Rng>(
        xsk: &ExtendedSpendingKey,
        password: &[u8],
        iters: u32,
        rng: &mut R,
    ) -> Result<Self> {
        assert!(iters != 0);
        let salt: [u8; 32] = rng.gen();
        let iv: [u8; 16] = rng.gen();

        let (derived_left, derived_right) = crypto::derive_key_iterations(password, &salt, iters);

        let xsk_bytes: Vec<u8> = xsk.try_into()?;

        let mut ciphertext: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; xsk_bytes.len()]);

        crypto::aes::encrypt_128_ctr(&derived_left, &iv, &xsk_bytes[..], &mut *ciphertext)
            .map_err(crypto::Error::from)?;

        let mac = crypto::derive_mac(&derived_right, &*ciphertext).keccak256();

        Ok(KeyCiphertext {
            ciphertext: ciphertext.into(),
            mac: mac.into(),
            salt: salt.into(),
            iv: iv.into(),
            iters,
        })
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<ExtendedSpendingKey> {
        let (derived_left, derived_right) =
            crypto::derive_key_iterations(password, &self.salt.0[..], self.iters);
        let mac = crypto::derive_mac(&derived_right, &self.ciphertext.0).keccak256();

        if !crypto::is_equal(&mac, &self.mac.0) {
            return Err(KeystoreError::InvalidPassword);
        }

        let mut plain: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; self.ciphertext.0.len()]);

        crypto::aes::decrypt_128_ctr(&derived_left, &self.iv.0, &self.ciphertext.0, &mut plain)
            .map_err(crypto::Error::from)?;

        let xsk = ExtendedSpendingKey::read(&mut &plain.to_vec()[..])?;

        Ok(xsk)
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Default, Clone)]
pub struct IndexFile {
    /// Default account index
    pub default_index: u32,

    /// Maximum account index
    pub max_index: u32,

    /// Default keyfile name
    pub default_keyfile_name: String,

    /// Mapping account_name to keyfile_name
    pub map_account_keyfile: HashMap<String, (String, u32)>,
}

impl IndexFile {
    pub fn set_default_index(
        mut self,
        new_index: u32,
        new_keyfile_name: &str,
        new_account_name: &str,
    ) -> Self {
        self.map_account_keyfile.extend(Some((
            new_account_name.to_string(),
            (new_keyfile_name.to_string(), new_index),
        )));

        IndexFile {
            default_index: new_index,
            max_index: self.max_index,
            default_keyfile_name: new_keyfile_name.to_string(),
            map_account_keyfile: self.map_account_keyfile,
        }
    }

    pub fn next_index(mut self, keyfile_name: &str, account_name: &str) -> Self {
        let next_index = self.max_index + 1;
        self.map_account_keyfile.extend(Some((
            account_name.to_string(),
            (keyfile_name.to_string(), next_index),
        )));

        IndexFile {
            default_index: next_index,
            max_index: next_index,
            default_keyfile_name: keyfile_name.to_string(),
            map_account_keyfile: self.map_account_keyfile,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_plain_with_correct_password() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();
        let xsk_master = ExtendedSpendingKey::master(&seed);

        let password = b"abcd";
        let iters = 1024;

        let ciphertext = KeyCiphertext::encrypt(&xsk_master, password, iters, rng).unwrap();
        let decrypted = ciphertext.decrypt(password).unwrap();

        assert_eq!(decrypted, xsk_master);
    }

    #[test]
    fn test_plain_with_wrong_password() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();
        let xsk_master = ExtendedSpendingKey::master(&seed);

        let password_enc = b"abcd";
        let password_dec = b"wxyz";
        let iters = 1024;

        let ciphertext = KeyCiphertext::encrypt(&xsk_master, password_enc, iters, rng).unwrap();
        let decrypted = ciphertext.decrypt(password_dec);

        assert_matches!(decrypted, Err(KeystoreError::InvalidPassword));
    }
}
