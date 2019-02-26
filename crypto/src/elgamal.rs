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
        secret_key: E::Fs, 
        p_g: FixedGenerators,
        params: &E::Params
    ) -> Option<u32> 
    {
        let sr_point = self.tbar.mul(secret_key, params);
        let neg_sr_point = sr_point.negate();
        let v_point = self.sbar.add(&neg_sr_point, params);

        for i in 0..u32::MAX {
            if find_point(i, &v_point, p_g, params) {
                return Some(i);
            }
        }

        None
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

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_elgamal_enc_dec() {

//     }
// }
