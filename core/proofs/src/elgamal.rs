//! (TODO) Alias module of `/core/crypto` crate due to std and no_std compatibility.

use scrypto::jubjub::{
        JubjubEngine,
        JubjubParams,
        edwards,
        PrimeOrder,
        FixedGenerators,
};
use crate::keys::{EncryptionKey, DecryptionKey};
use blake2_rfc::{
    blake2b::{Blake2b, Blake2bResult}
};
use std::io;
use zcrypto::constants::ELGAMAL_EXTEND_PERSONALIZATION;

#[derive(Clone, PartialEq, Debug)]
pub struct Ciphertext<E: JubjubEngine> {
    pub left: edwards::Point<E, PrimeOrder>,
    pub right: edwards::Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> Ciphertext<E> {
    pub fn new(
        left: edwards::Point<E, PrimeOrder>,
        right: edwards::Point<E, PrimeOrder>
    ) -> Self
    {
        Ciphertext {
            left,
            right,
        }
    }

    pub fn zero() -> Self {
        Ciphertext {
            left: edwards::Point::zero(),
            right: edwards::Point::zero()
        }
    }

    pub fn encrypt(
        value: u32, // 32-bits restriction for the decryption.
        randomness: E::Fs,
        public_key: &EncryptionKey<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Self
    {
        let right = params.generator(p_g).mul(randomness, params).into();
        let v_point: edwards::Point<E, PrimeOrder> = params.generator(p_g).mul(value as u64, params).into();
        let r_point = public_key.0.mul(randomness, params);
        let left = v_point.add(&r_point, params);

        Ciphertext {
            left,
            right,
        }
    }

    /// Decryption of the ciphetext for the value
    pub fn decrypt(
        &self,
        decryption_key: &DecryptionKey<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Option<u32>
    {
        let sr_point = self.right.mul(decryption_key.0, params);
        let neg_sr_point = sr_point.negate();
        let v_point = self.left.add(&neg_sr_point, params);

        let one = params.generator(p_g);
        let mut acc = edwards::Point::<E, PrimeOrder>::zero();

        // Brute-force decryption
        for i in 0..1_000_000 {
            if acc == v_point {
                return Some(i)
            }
            acc = acc.add(&one, params);
        }

        None
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.left.write(&mut writer)?;
        self.right.write(&mut writer)?;
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let mut buf = [0u8; 64];
        reader.read_exact(&mut buf[..]).unwrap();

        let left = edwards::Point::<E, _>::read(&mut &buf[..32], params)?;
        let left = match left.as_prime_order(params) {
            Some(l) => l,
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Not on curve")),
        };

        let right = edwards::Point::<E, _>::read(&mut &buf[32..], params)?;
        let right = match right.as_prime_order(params) {
            Some(r) => r,
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "Not on curve")),
        };

        Ok(Ciphertext {
            left,
            right,
        })
    }

    /// Addition of elgamal ciphertext
    pub fn add(&self, other: &Self, params: &E::Params) -> Self {
        let left = self.left.add(&other.left, params);
        let right = self.right.add(&other.right, params);
        Ciphertext {
            left,
            right,
        }
    }

    /// Subtraction of elgamal ciphertext
    pub fn sub(&self, other: &Self, params: &E::Params) -> Self {
        let left = self.left.add(&other.left.negate(), params);
        let right = self.right.add(&other.right.negate(), params);
        Ciphertext {
            left,
            right,
        }
    }
}

/// Extend the secret key to 64 bits for the scalar field generation.
pub fn elgamal_extend(sk: &[u8]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], ELGAMAL_EXTEND_PERSONALIZATION);
    h.update(sk);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rand};
    use scrypto::jubjub::{JubjubBls12, fs::Fs};
    use pairing::bls12_381::Bls12;
    use crate::keys::{ProofGenerationKey, EncryptionKey};

    #[test]
    fn test_elgamal_enc_dec() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let value: u32 = 5 as u32;

        let sk_fs = Fs::rand(rng);
        let r_fs = Fs::rand(rng);

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));

        let ciphetext = Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);
        let decrypted_value = ciphetext.decrypt(&DecryptionKey(sk_fs), p_g, params).unwrap();

        assert_eq!(value, decrypted_value);
    }

    #[test]
    fn test_elgamal_enc_dec_ivk() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let alice_seed = b"Alice                           ";
        let alice_value = 100 as u32;

        let r_fs = Fs::rand(rng);

        let address = EncryptionKey::<Bls12>::from_seed(alice_seed, params).unwrap();
	    let enc_alice_val = Ciphertext::encrypt(alice_value, r_fs, &address, p_g, params);

        let bdk = ProofGenerationKey::<Bls12>::from_seed(alice_seed, params).into_decryption_key().unwrap();

        let dec_alice_val = enc_alice_val.decrypt(&bdk, p_g, params).unwrap();
	    assert_eq!(dec_alice_val, alice_value);
    }

    #[test]
    fn test_homomorphic_correct_public_key() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let sk_fs = Fs::rand(rng);
        let r_fs1 = Fs::rand(rng);
        let r_fs2 = Fs::rand(rng);

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let value20: u32 = 20 as u32;
        let value13: u32 = 13 as u32;
        let value7: u32 = 7 as u32;

        let ciphetext20 = Ciphertext::encrypt(value20, r_fs1, &public_key, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(value13, r_fs2, &public_key, p_g, params);

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let decrypted_value7 = homo_ciphetext7.decrypt(&DecryptionKey(sk_fs), p_g, params).unwrap();
        assert_eq!(decrypted_value7, value7);
    }

    #[test]
    #[should_panic]
    fn test_homomorphic_wrong_public_key() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs1 = Fs::rand(rng);
        let sk_fs2 = Fs::rand(rng);
        let r_fs1 = Fs::rand(rng);
        let r_fs2 = Fs::rand(rng);

        let public_key1 = EncryptionKey(params.generator(p_g).mul(sk_fs1, params));
        let public_key2 = EncryptionKey(params.generator(p_g).mul(sk_fs2, params));
        let value20: u32 = 20 as u32;
        let value13: u32 = 13 as u32;
        let value7: u32 = 7 as u32;

        let ciphetext20 = Ciphertext::encrypt(value20, r_fs1, &public_key1, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(value13, r_fs2, &public_key2, p_g, params);

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let expected_value7 = homo_ciphetext7.decrypt(&DecryptionKey(sk_fs1), p_g, params).unwrap();
        assert_eq!(expected_value7, value7);
    }

    #[test]
    fn test_ciphertext_read_write() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs = Fs::rand(rng);
        let r_fs = Fs::rand(rng);

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let value: u32 = 6 as u32;

        let ciphetext1 = Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);

        let mut v = vec![];
        ciphetext1.write(&mut v).unwrap();
        let ciphetext2 = Ciphertext::read(&mut &v[..], params).unwrap();

        assert!(ciphetext1 == ciphetext2);
    }
}
