use fixed_hash::construct_fixed_hash;
#[cfg(test)]
use pairing::bls12_381::Bls12;
#[cfg(test)]
use jubjub::curve::{edwards, PrimeOrder, Unknown};

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct Nonce(SIZE);
}

impl_fixed_hash_codec!(Nonce, SIZE);
impl_edwards_point_conversions!(Nonce, SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use jubjub::curve::JubjubBls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_convert_types() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let point1 = edwards::Point::<Bls12, Unknown>::rand(rng, params).mul_by_cofactor(params);
        let nonce = Nonce::try_from(point1.clone()).unwrap();
        let point2 = edwards::Point::try_from(nonce).unwrap();

        assert_eq!(point1, point2);
    }
}
