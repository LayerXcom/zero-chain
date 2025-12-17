use crate::PARAMS;
use fixed_hash::construct_fixed_hash;
use jubjub::curve::{JubjubBls12, edwards, PrimeOrder};
#[cfg(test)]
use jubjub::curve::Unknown;
use jubjub::group_hash::group_hash;
use pairing::{
    bls12_381::Bls12,
    io
};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryFrom;

const SIZE: usize = 32;
const GEPOCH_PERSONALIZATION: &[u8; 8] = b"zcgepoch";

construct_fixed_hash! {
    pub struct GEpoch(SIZE);
}

impl_fixed_hash_codec!(GEpoch, SIZE);
impl_edwards_point_conversions!(GEpoch, SIZE);

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
