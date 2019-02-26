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
use pairing::{PrimeField, io};

pub const ELGAMAL_EXTEND_PERSONALIZATION: &'static [u8; 16] = b"zech_elgamal_ext";

#[derive(Clone, PartialEq)]
pub struct Ciphertext<E: JubjubEngine> {
    sbar: edwards::Point<E, PrimeOrder>,
    tbar: edwards::Point<E, PrimeOrder>,
}

impl<E: JubjubEngine> Ciphertext<E> {
    pub fn encrypt(
        value: u32, // 32-bits restriction for the decryption.
        randomness: E::Fs,
        public_key: &edwards::Point<E, PrimeOrder>,
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Self
    {
        let tbar = params.generator(p_g).mul(randomness, params).into();
        let v_point: edwards::Point<E, PrimeOrder> = params.generator(p_g).mul(value as u64, params).into();
        let r_point = public_key.mul(randomness, params);
        let sbar = v_point.add(&r_point, params);

        Ciphertext {
            sbar,
            tbar,
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
        let sr_point = self.tbar.mul(sk_fs, params);
        let neg_sr_point = sr_point.negate();
        let v_point = self.sbar.add(&neg_sr_point, params);

        for i in 0..u32::MAX {
            if find_point(i, &v_point, p_g, params) {
                return Some(i);
            }
        }

        None
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.sbar.write(&mut writer)?;
        self.tbar.write(&mut writer)?;
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let sbar = edwards::Point::<E, _>::read(reader, params)?;
        let sbar = sbar.as_prime_order(params).unwrap();

        let tbar = edwards::Point::<E, _>::read(reader, params)?;
        let tbar = tbar.as_prime_order(params).unwrap();

        Ok(Ciphertext {
            sbar,
            tbar,
        })
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
fn elgamal_extend(sk: &[u8]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], ELGAMAL_EXTEND_PERSONALIZATION);
    h.update(sk);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rand, Rng, SeedableRng, XorShiftRng};
    use jubjub::curve::{JubjubBls12, fs::Fs};

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
    fn test_homomorphic() {
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
        let value20: u32 = 20 as u32;
        let value13: u32 = 13 as u32;
        let value7: u32 = 7 as u32;

        let ciphetext20 = Ciphertext::encrypt(value20, r_fs, &public_key, p_g, params);
        let ciphetext13 = Ciphertext::encrypt(value13, r_fs, &public_key, p_g, params);

        let neg_s_ciphertext13 = ciphetext13.sbar.negate();
        let neg_t_ciphertext13 = ciphetext13.tbar.negate();
        let s_ciphertext7 = ciphetext20.sbar.add(&neg_s_ciphertext13, params);
        let t_ciphertext7 = ciphetext20.tbar.add(&neg_t_ciphertext13, params);

        let homo_ciphetext7 = Ciphertext {
            sbar: s_ciphertext7,
            tbar: t_ciphertext7,
        };

        let decrypted_value7 = homo_ciphetext7.decrypt(&sk, p_g, params).unwrap();    
        assert_eq!(decrypted_value7, value7);       
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
