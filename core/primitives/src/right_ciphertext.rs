use fixed_hash::construct_fixed_hash;
#[cfg(test)]
use pairing::bls12_381::Bls12;
#[cfg(test)]
use jubjub::curve::{edwards, PrimeOrder, Unknown};
#[cfg(test)]
use zcrypto::elgamal;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct RightCiphertext(SIZE);
}

impl_fixed_hash_codec!(RightCiphertext, SIZE);
impl_edwards_point_conversions!(RightCiphertext, SIZE);
impl_ciphertext_component_conversion!(RightCiphertext, right, SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use jubjub::curve::JubjubBls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_convert_types() {
        let params = &JubjubBls12::new();
        let rng_right = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let rng_left = &mut XorShiftRng::from_seed([0x33be6558, 0x8d313576, 0x3237db13, 0xe5dc0654]);

        let right_point = edwards::Point::<Bls12, Unknown>::rand(rng_right, params).mul_by_cofactor(params);
        let left_point = edwards::Point::<Bls12, Unknown>::rand(rng_left, params).mul_by_cofactor(params);

        let ciphertext = elgamal::Ciphertext::new(left_point.clone(), right_point.clone());
        let right_ciphertext = RightCiphertext::try_from(ciphertext).unwrap();
        let right_point2 = edwards::Point::try_from(right_ciphertext).unwrap();

        assert_eq!(right_point, right_point2.clone());
        assert_ne!(left_point, right_point2);
    }
}
