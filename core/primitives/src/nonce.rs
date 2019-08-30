#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
#[cfg(feature = "std")]
use substrate_primitives::bytes;
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;
use crate::PARAMS;
use crate::IntoXY;
use fixed_hash::construct_fixed_hash;
use pairing::bls12_381::{Bls12, Fr};
use jubjub::curve::{edwards, PrimeOrder, Unknown};
use pairing::io;
use parity_codec::{Encode, Decode, Input};
use core::convert::TryFrom;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct H256(SIZE);
}

pub type Nonce = H256;

#[cfg(feature = "std")]
impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| Nonce::from_slice(&x))
    }
}

impl Encode for Nonce {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for Nonce {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H256)
    }
}

impl TryFrom<edwards::Point<Bls12, PrimeOrder>> for Nonce {
    type Error = io::Error;

    fn try_from(point: edwards::Point<Bls12, PrimeOrder>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        point.write(&mut &mut writer[..])?;

        Ok(H256::from_slice(&writer[..]))
    }
}

impl TryFrom<Nonce> for edwards::Point<Bls12, PrimeOrder> {
    type Error = io::Error;

    fn try_from(nonce: Nonce) -> Result<Self, io::Error> {
        let mut bytes = nonce.as_bytes();

        edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::NotInField)
    }
}

impl TryFrom<&Nonce> for edwards::Point<Bls12, PrimeOrder> {
    type Error = io::Error;

    fn try_from(nonce: &Nonce) -> Result<Self, io::Error> {
        let mut bytes = nonce.as_bytes();

        edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::NotInField)
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for Nonce {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl IntoXY<Bls12> for Nonce {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = edwards::Point::<Bls12, PrimeOrder>::try_from(self)?
            .into_xy();

        Ok(point)
    }
}

impl IntoXY<Bls12> for &Nonce {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = edwards::Point::<Bls12, PrimeOrder>::try_from(**self)?
            .into_xy();

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
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let point1 = edwards::Point::<Bls12, Unknown>::rand(rng, params).mul_by_cofactor(params);
        let nonce = Nonce::try_from(point1.clone()).unwrap();
        let point2 = edwards::Point::try_from(nonce).unwrap();

        assert_eq!(point1, point2);
    }
}
