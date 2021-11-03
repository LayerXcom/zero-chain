use crate::{IntoXY, PARAMS};
use core::convert::TryFrom;
use fixed_hash::construct_fixed_hash;
use jubjub::curve::{edwards, PrimeOrder, Unknown};
use pairing::bls12_381::{Bls12, Fr};
use pairing::io;
use parity_codec::{Decode, Encode, Input};
#[cfg(feature = "std")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "std")]
use substrate_primitives::bytes;
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;
use zcrypto::elgamal;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct H256(SIZE);
}

pub type RightCiphertext = H256;

#[cfg(feature = "std")]
impl Serialize for RightCiphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for RightCiphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| RightCiphertext::from_slice(&x))
    }
}

impl Encode for RightCiphertext {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for RightCiphertext {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H256)
    }
}

impl TryFrom<elgamal::Ciphertext<Bls12>> for RightCiphertext {
    type Error = io::Error;

    fn try_from(ciphertext: elgamal::Ciphertext<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        ciphertext.right.write(&mut &mut writer[..])?;

        Ok(H256::from_slice(&writer[..]))
    }
}

impl TryFrom<RightCiphertext> for edwards::Point<Bls12, PrimeOrder> {
    type Error = io::Error;

    fn try_from(right_ciphertext: RightCiphertext) -> Result<Self, io::Error> {
        let mut bytes = right_ciphertext.as_bytes();

        edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::NotInField)
    }
}

impl TryFrom<&RightCiphertext> for edwards::Point<Bls12, PrimeOrder> {
    type Error = io::Error;

    fn try_from(right_ciphertext: &RightCiphertext) -> Result<Self, io::Error> {
        let mut bytes = right_ciphertext.as_bytes();

        edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::NotInField)
    }
}

impl TryFrom<edwards::Point<Bls12, PrimeOrder>> for RightCiphertext {
    type Error = io::Error;

    fn try_from(point: edwards::Point<Bls12, PrimeOrder>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        point.write(&mut &mut writer[..])?;

        Ok(H256::from_slice(&writer[..]))
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for RightCiphertext {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl IntoXY<Bls12> for RightCiphertext {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = edwards::Point::<Bls12, PrimeOrder>::try_from(self)?.into_xy();

        Ok(point)
    }
}

impl IntoXY<Bls12> for &RightCiphertext {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = edwards::Point::<Bls12, PrimeOrder>::try_from(**self)?.into_xy();

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jubjub::curve::JubjubBls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_convert_types() {
        let params = &JubjubBls12::new();
        let rng_right =
            &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let rng_left =
            &mut XorShiftRng::from_seed([0x33be6558, 0x8d313576, 0x3237db13, 0xe5dc0654]);

        let right_point =
            edwards::Point::<Bls12, Unknown>::rand(rng_right, params).mul_by_cofactor(params);
        let left_point =
            edwards::Point::<Bls12, Unknown>::rand(rng_left, params).mul_by_cofactor(params);

        let ciphertext = elgamal::Ciphertext::new(left_point.clone(), right_point.clone());
        let right_ciphertext = RightCiphertext::try_from(ciphertext).unwrap();
        let right_point2 = edwards::Point::try_from(right_ciphertext).unwrap();

        assert_eq!(right_point, right_point2.clone());
        assert_ne!(left_point, right_point2);
    }
}
