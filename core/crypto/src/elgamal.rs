#[cfg(feature = "std")]
use ::std::u32;
#[cfg(not(feature = "std"))]
use crate::std::u32;

use jubjub::curve::{
        JubjubEngine,
        JubjubParams,
        edwards,
        PrimeOrder,
        FixedGenerators,
};
use blake2_rfc::{
    blake2b::{Blake2b, Blake2bResult}
};
use pairing::io;

/// The constant personalization for elgamal extending function
pub const ELGAMAL_EXTEND_PERSONALIZATION: &'static [u8; 16] = b"zech_elgamal_ext";

/// lifted-Elgamal encryption
/// Enc(m) = (m + rs)G, rG), where m: message, r: randomness, s: private key, G: Generator point
#[derive(Clone, PartialEq)]
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
        amount: u32, // 32-bits restriction for the decryption.
        randomness: &E::Fs,
        enc_key: &keys::EncryptionKey<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Self
    {
        let right = params.generator(p_g).mul(*randomness, params);
        let v_point = params.generator(p_g).mul(amount as u64, params);
        let r_point = enc_key.0.mul(*randomness, params);
        let left = v_point.add(&r_point, params);

        Ciphertext {
            left,
            right,
        }
    }

    // Encrypt with negative value
    pub fn neg_encrypt(
        amount: u32,
        randomness: &E::Fs,
        enc_key: &keys::EncryptionKey<E>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Self {
        let right = params.generator(p_g).mul(*randomness, params);
        let v_point = params.generator(p_g).mul(amount as u64, params).negate();
        let r_point = enc_key.0.mul(*randomness, params);
        let left = v_point.add(&r_point, params);

        Ciphertext {
            left,
            right,
        }
    }

    /// Decryption of the ciphetext for the amount
    pub fn decrypt(
        &self,
        decryption_key: &keys::DecryptionKey<E>,
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
        let left = edwards::Point::<E, _>::read(reader, params)?;
        let left = match left.as_prime_order(params) {
            Some(l) => l,
            None => return Err(io::Error::NotOnCurve),
        };

        let right = edwards::Point::<E, _>::read(reader, params)?;
        let right = match right.as_prime_order(params) {
            Some(r) => r,
            None => return Err(io::Error::NotOnCurve),
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

    /// Addition of elgamal ciphertext without params
    pub fn add_no_params(&self, other: &Self) -> Self {
        let left = self.left.add_no_params(&other.left);
        let right = self.right.add_no_params(&other.right);

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

    /// Subtraction of elgamal ciphertext without params
    pub fn sub_no_params(&self, other: &Self) -> Self {
        let left = self.left.add_no_params(&other.left.negate());
        let right = self.right.add_no_params(&other.right.negate());

        Ciphertext {
            left,
            right
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
    use jubjub::curve::{JubjubBls12, fs::Fs};
    use pairing::bls12_381::Bls12;
    use keys::{ProofGenerationKey, EncryptionKey, DecryptionKey};

    #[test]
    fn test_elgamal_enc_dec() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let amount = 5;

        let sk_fs = Fs::rand(rng);
        let r_fs = Fs::rand(rng);

        let enc_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));

        let ciphetext = Ciphertext::encrypt(amount, &r_fs, &enc_key, p_g, params);
        let decrypted_amount = ciphetext.decrypt(&DecryptionKey(sk_fs), p_g, params).unwrap();

        assert_eq!(amount, decrypted_amount);
    }

    #[test]
    fn test_elgamal_enc_dec_ivk() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let alice_seed = b"Alice                           ";
        let alice_amount = 100;

        let r_fs = Fs::rand(rng);

        let address = EncryptionKey::<Bls12>::from_seed(alice_seed, params).unwrap();
	    let enc_alice_val = Ciphertext::encrypt(alice_amount, &r_fs, &address, p_g, params);

        let bdk = ProofGenerationKey::<Bls12>::from_seed(alice_seed, params).into_decryption_key().unwrap();

        let dec_alice_val = enc_alice_val.decrypt(&bdk, p_g, params).unwrap();
	    assert_eq!(dec_alice_val, alice_amount);
    }

    #[test]
    fn test_homomorphic_correct_enc_key() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs = Fs::rand(rng);
        let r_fs1 = Fs::rand(rng);
        let r_fs2 = Fs::rand(rng);

        let enc_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let amount20 = 20;
        let amount13 = 13;
        let amount7 = 7;

        let ciphetext20 = Ciphertext::encrypt(amount20, &r_fs1, &enc_key, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(amount13, &r_fs2, &enc_key, p_g, params);

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let decryption_key = DecryptionKey(sk_fs);

        let decrypted_amount7 = homo_ciphetext7.decrypt(&decryption_key, p_g, params).unwrap();
        assert_eq!(decrypted_amount7, amount7);
    }

    #[test]
    fn test_add_no_params() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs = Fs::rand(rng);
        let r_fs1 = Fs::rand(rng);
        let r_fs2 = Fs::rand(rng);

        let enc_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let amount15 = 15;
        let amount4 = 4;
        let amount19 = 19;

        let ciphetext15 = Ciphertext::encrypt(amount15, &r_fs1, &enc_key, p_g, params);
        let ciphetext4 = Ciphertext::encrypt(amount4, &r_fs2, &enc_key, p_g, params);

        let homo_ciphetext19 = ciphetext15.add_no_params(&ciphetext4);
        let homo_ciphetext19_params = ciphetext15.add(&ciphetext4, params);

        let decryption_key = DecryptionKey(sk_fs);

        let decrypted_amount19 = homo_ciphetext19.decrypt(&decryption_key, p_g, params).unwrap();
        let decrypted_amount19_params = homo_ciphetext19_params.decrypt(&decryption_key, p_g, params).unwrap();

        assert_eq!(decrypted_amount19, amount19);
        assert!(homo_ciphetext19 == homo_ciphetext19_params);
        assert_eq!(decrypted_amount19, decrypted_amount19_params);
    }

    #[test]
    #[should_panic]
    fn test_homomorphic_wrong_enc_key() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs1 = Fs::rand(rng);
        let sk_fs2 = Fs::rand(rng);
        let r_fs1 = Fs::rand(rng);
        let r_fs2 = Fs::rand(rng);

        let enc_key1 = EncryptionKey(params.generator(p_g).mul(sk_fs1, params));
        let enc_key2 = EncryptionKey(params.generator(p_g).mul(sk_fs2, params));
        let amount20 = 20;
        let amount13 = 13;
        let amount7 = 7;

        let ciphetext20 = Ciphertext::encrypt(amount20, &r_fs1, &enc_key1, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(amount13, &r_fs2, &enc_key2, p_g, params);

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let decryption_key = DecryptionKey(sk_fs1);

        let expected_amount7 = homo_ciphetext7.decrypt(&decryption_key, p_g, params).unwrap();
        assert_eq!(expected_amount7, amount7);
    }

    #[test]
    fn test_ciphertext_read_write() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let sk_fs = Fs::rand(rng);
        let r_fs = Fs::rand(rng);

        let enc_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let amount = 6;

        let ciphetext1 = Ciphertext::encrypt(amount, &r_fs, &enc_key, p_g, params);

        let mut v = vec![];
        ciphetext1.write(&mut v).unwrap();
        let ciphetext2 = Ciphertext::read(&mut v.as_slice(), params).unwrap();
        assert!(ciphetext1 == ciphetext2);
    }
}
