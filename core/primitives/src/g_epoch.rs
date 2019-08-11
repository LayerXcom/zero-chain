#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
#[cfg(feature = "std")]
use substrate_primitives::bytes;
use crate::PARAMS;
use fixed_hash::construct_fixed_hash;
use jubjub::curve::{JubjubBls12, edwards, PrimeOrder, Unknown};
use jubjub::group_hash::group_hash;
use pairing::bls12_381::Bls12;
use pairing::io;
use parity_codec::{Encode, Decode, Input};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;

const SIZE: usize = 32;
const GEPOCH_PERSONALIZATION: &[u8; 8] = b"zcgepoch";

construct_fixed_hash! {
    pub struct H256(SIZE);
}

pub type GEpoch = H256;

#[cfg(feature = "std")]
impl Serialize for GEpoch {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for GEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| GEpoch::from_slice(&x))
    }
}

impl Encode for GEpoch {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for GEpoch {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H256)
    }
}

impl TryFrom<edwards::Point<Bls12, PrimeOrder>> for GEpoch {
    type Error = io::Error;

    fn try_from(point: edwards::Point<Bls12, PrimeOrder>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        point.write(&mut &mut writer[..])?;

        Ok(H256::from_slice(&writer[..]))
    }
}

impl TryFrom<GEpoch> for edwards::Point<Bls12, PrimeOrder> {
    type Error = io::Error;

    fn try_from(g_epoch: GEpoch) -> Result<Self, io::Error> {
        let mut bytes = g_epoch.as_bytes();

        edwards::Point::<Bls12, Unknown>::read(&mut bytes, &PARAMS)?
            .as_prime_order(&PARAMS)
            .ok_or(io::Error::NotInField)
    }
}

impl GEpoch {
    pub fn try_new() -> Result<Self, io::Error> {
        let mut new_epoch = [0u8; 4];
        LittleEndian::write_u32(&mut new_epoch, 0);

        // Hash_to_curve(GEPOCH_PERSONALIZATION || 0)
        let new_g_epoch = find_group_hash(&new_epoch, GEPOCH_PERSONALIZATION, &PARAMS);
        GEpoch::try_from(new_g_epoch)
    }

    pub fn group_hash(curr_epoch: u32) -> Result<Self, io::Error> {
        let mut epoch = [0u8; 4];
        LittleEndian::write_u32(&mut epoch, curr_epoch);

        // Hash_to_curve(GEPOCH_PERSONALIZATION || current_epoch)
        let g_epoch = find_group_hash(&epoch, GEPOCH_PERSONALIZATION, &PARAMS);
        GEpoch::try_from(g_epoch)
    }
}

fn find_group_hash(
    m: &[u8],
    personalization: &[u8; 8],
    params: &JubjubBls12
) -> edwards::Point<Bls12, PrimeOrder>
{
    let mut tag = m.to_vec();
    let i = tag.len();
    tag.push(0u8);

    loop {
        let gh = group_hash(
            &tag,
            personalization,
            params
        );

        // We don't want to overflow and start reusing generators
        assert!(tag[i] != u8::max_value());
        tag[i] += 1;

        if let Some(gh) = gh {
            break gh;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn test_convert_types() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let point1 = edwards::Point::<Bls12, Unknown>::rand(rng, params).mul_by_cofactor(params);
        let g_epoch = GEpoch::try_from(point1.clone()).unwrap();
        let point2 = edwards::Point::try_from(g_epoch).unwrap();

        assert_eq!(point1, point2);
    }

    #[test]
    fn test_group_hash() {
        let new_g_epoch = GEpoch::try_new().unwrap();
        let zero_g_epch = GEpoch::group_hash(0).unwrap();
        println!("zero: {:?}", new_g_epoch);
        assert_eq!(new_g_epoch, zero_g_epch);
    }
}
