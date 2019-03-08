use jubjub::curve::{
        JubjubEngine,
        JubjubParams,
        edwards,
        PrimeOrder,
        FixedGenerators,
        ToUniform,
};

#[cfg(feature = "std")]
use ::std::u32;
#[cfg(not(feature = "std"))]
use crate::std::u32;

use blake2_rfc::{
    blake2b::{Blake2b, Blake2bResult}
};
use pairing::io;

pub const ELGAMAL_EXTEND_PERSONALIZATION: &'static [u8; 16] = b"zech_elgamal_ext";

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

    pub fn encrypt(
        value: u32, // 32-bits restriction for the decryption.
        randomness: E::Fs,
        public_key: &edwards::Point<E, PrimeOrder>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Self
    {
        let right = params.generator(p_g).mul(randomness, params).into();
        let v_point: edwards::Point<E, PrimeOrder> = params.generator(p_g).mul(value as u64, params).into();
        let r_point = public_key.mul(randomness, params);
        let left = v_point.add(&r_point, params);

        Ciphertext {
            left,
            right,
        }
    }

    /// Decryption of the ciphetext for the value
    pub fn decrypt(
        &self, 
        sk: &[u8], 
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Option<u32> 
    {
        let sk_fs = E::Fs::to_uniform(elgamal_extend(sk).as_bytes());
        let sr_point = self.right.mul(sk_fs, params);
        let neg_sr_point = sr_point.negate();
        let v_point = self.left.add(&neg_sr_point, params);

        // for i in 0..u32::MAX {
        for i in 0..1000 { // FIXME:
            if find_point(i, &v_point, p_g, params) {
                return Some(i);
            }
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

/// Find the point of the value
fn find_point<E: JubjubEngine>(
    value: u32, 
    point: &edwards::Point<E, PrimeOrder>,
    p_g: FixedGenerators,
    params: &E::Params
) -> bool 
{
    let v_point: edwards::Point<E, PrimeOrder> = params.generator(p_g).mul(value as u64, params).into();
    &v_point == point
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
    use rand::{Rng, SeedableRng, XorShiftRng};
    use jubjub::curve::{JubjubBls12, fs::Fs};
    use pairing::PrimeField;

    #[test]
    fn test_elgamal_enc_dec() {
        let rng_sk = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal_extend(&sk).as_bytes()).into_repr();

        let rng_r = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r.fill_bytes(&mut randomness[..]);
        let r_fs = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::ElGamal;

        let public_key = params.generator(p_g).mul(sk_fs, params).into();
        let value: u32 = 5 as u32;

        let ciphetext = Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);
        let decrypted_value = ciphetext.decrypt(&sk, p_g, params).unwrap();

        assert_eq!(value, decrypted_value);
    }

    #[test]
    fn test_homomorphic_correct_public_key() {
        let rng_sk = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal_extend(&sk).as_bytes());

        let rng_r1 = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r1.fill_bytes(&mut randomness[..]);
        let r_fs1 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let rng_r2 = &mut XorShiftRng::from_seed([0xbc4f6d37, 0xd32f276d, 0xb943afd3, 0x54598639]);
        let mut randomness = [0u8; 32];
        rng_r2.fill_bytes(&mut randomness[..]);
        let r_fs2 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::ElGamal;

        let public_key = params.generator(p_g).mul(sk_fs, params).into();
        let value20: u32 = 20 as u32;
        let value13: u32 = 13 as u32;        
        let value7: u32 = 7 as u32;

        let ciphetext20 = Ciphertext::encrypt(value20, r_fs1, &public_key, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(value13, r_fs2, &public_key, p_g, params);

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let decrypted_value7 = homo_ciphetext7.decrypt(&sk, p_g, params).unwrap();    
        assert_eq!(decrypted_value7, value7);       
    }

    #[test]
    fn test_add_no_params() {
        let rng_sk = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal_extend(&sk).as_bytes());

        let rng_r1 = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r1.fill_bytes(&mut randomness[..]);
        let r_fs1 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let rng_r2 = &mut XorShiftRng::from_seed([0xbc4f6d37, 0xd32f276d, 0xb943afd3, 0x54598639]);
        let mut randomness = [0u8; 32];
        rng_r2.fill_bytes(&mut randomness[..]);
        let r_fs2 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::ElGamal;

        let public_key = params.generator(p_g).mul(sk_fs, params).into();
        let value15: u32 = 15 as u32;
        let value4: u32 = 4 as u32;        
        let value19: u32 = 19 as u32;

        let ciphetext15 = Ciphertext::encrypt(value15, r_fs1, &public_key, p_g, params);
        let ciphetext4 = Ciphertext::encrypt(value4, r_fs2, &public_key, p_g, params);

        let homo_ciphetext19 = ciphetext15.add_no_params(&ciphetext4);
        let homo_ciphetext19_params = ciphetext15.add(&ciphetext4, params);

        let decrypted_value19 = homo_ciphetext19.decrypt(&sk, p_g, params).unwrap();    
        let decrypted_value19_params = homo_ciphetext19_params.decrypt(&sk, p_g, params).unwrap();

        assert_eq!(decrypted_value19, value19);
        assert!(homo_ciphetext19 == homo_ciphetext19_params);
        assert_eq!(decrypted_value19, decrypted_value19_params);
    }
        
    #[test]
    #[should_panic]
    fn test_homomorphic_wrong_public_key() {
        let rng_sk1 = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let mut sk1 = [0u8; 32];
        rng_sk1.fill_bytes(&mut sk1[..]);
        let sk_fs1 = Fs::to_uniform(elgamal_extend(&sk1).as_bytes());

        let rng_sk2 = &mut XorShiftRng::from_seed([0xbc4f6d74, 0xd32f276c, 0xb913afd0, 0x9455863d]);
        let mut sk2 = [0u8; 32];
        rng_sk2.fill_bytes(&mut sk2[..]);
        let sk_fs2 = Fs::to_uniform(elgamal_extend(&sk2).as_bytes());

        let rng_r1 = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r1.fill_bytes(&mut randomness[..]);
        let r_fs1 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let rng_r2 = &mut XorShiftRng::from_seed([0xbc4f6d37, 0xd32f276d, 0xb943afd3, 0x54598639]);
        let mut randomness = [0u8; 32];
        rng_r2.fill_bytes(&mut randomness[..]);
        let r_fs2 = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::ElGamal;

        let public_key1 = params.generator(p_g).mul(sk_fs1, params).into();
        let public_key2 = params.generator(p_g).mul(sk_fs2, params).into();
        let value20: u32 = 20 as u32;
        let value13: u32 = 13 as u32;        
        let value7: u32 = 7 as u32;

        let ciphetext20 = Ciphertext::encrypt(value20, r_fs1, &public_key1, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(value13, r_fs2, &public_key2, p_g, params);        

        let homo_ciphetext7 = ciphetext20.sub(&ciphetext13, params);

        let expected_value7 = homo_ciphetext7.decrypt(&sk1, p_g, params).unwrap();        
        assert_eq!(expected_value7, value7);   
    }

    #[test]
    fn test_ciphertext_read_write() {
        let rng_sk = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal_extend(&sk).as_bytes()).into_repr();

        let rng_r = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r.fill_bytes(&mut randomness[..]);
        let r_fs = Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::ElGamal;

        let public_key = params.generator(p_g).mul(sk_fs, params).into();
        let value: u32 = 6 as u32;

        let ciphetext1 = Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);

        let mut v = vec![];
        ciphetext1.write(&mut v).unwrap();
        let ciphetext2 = Ciphertext::read(&mut v.as_slice(), params).unwrap();
        assert!(ciphetext1 == ciphetext2);
    }
}
