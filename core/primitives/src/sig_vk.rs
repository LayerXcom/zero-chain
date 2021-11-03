use crate::{IntoXY, PARAMS};
use core::convert::TryFrom;
use fixed_hash::construct_fixed_hash;
use jubjub::redjubjub;
use pairing::{
    bls12_381::{Bls12, Fr},
    io,
};
use parity_codec::{Decode, Encode, Input};
#[cfg(feature = "std")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "std")]
use substrate_primitives::bytes;
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct H256(SIZE);
}

pub type SigVerificationKey = H256;

#[cfg(feature = "std")]
impl Serialize for SigVerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for SigVerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| SigVerificationKey::from_slice(&x))
    }
}

impl Encode for SigVerificationKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for SigVerificationKey {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H256)
    }
}

impl TryFrom<redjubjub::PublicKey<Bls12>> for SigVerificationKey {
    type Error = io::Error;

    fn try_from(vk: redjubjub::PublicKey<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        vk.write(&mut &mut writer[..]).unwrap();

        Ok(H256::from_slice(&writer))
    }
}

impl TryFrom<SigVerificationKey> for redjubjub::PublicKey<Bls12> {
    type Error = io::Error;

    fn try_from(sig_vk: SigVerificationKey) -> Result<Self, io::Error> {
        redjubjub::PublicKey::read(&mut &sig_vk.0[..], &*PARAMS)
    }
}

impl TryFrom<&SigVerificationKey> for redjubjub::PublicKey<Bls12> {
    type Error = io::Error;

    fn try_from(sig_vk: &SigVerificationKey) -> Result<Self, io::Error> {
        redjubjub::PublicKey::read(&mut &sig_vk.0[..], &*PARAMS)
    }
}

impl IntoXY<Bls12> for SigVerificationKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = redjubjub::PublicKey::<Bls12>::try_from(self)?
            .0
            .as_prime_order(&*PARAMS) // TODO: Consider cofactor
            .ok_or(io::Error::NotInField)?
            .into_xy();

        Ok(point)
    }
}

impl IntoXY<Bls12> for &SigVerificationKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = redjubjub::PublicKey::<Bls12>::try_from(**self)?
            .0
            .as_prime_order(&*PARAMS) // TODO: Consider cofactor
            .ok_or(io::Error::NotInField)?
            .into_xy();

        Ok(point)
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for SigVerificationKey {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

pub trait SigVk {}
impl SigVk for SigVerificationKey {}
impl SigVk for &SigVerificationKey {}
impl SigVk for u64 {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryInto;
    use jubjub::curve::{FixedGenerators, JubjubBls12};
    use jubjub::redjubjub::PublicKey;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_vk_into_from() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::Diversifier;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk1 = PublicKey::from_private(&sk, p_g, params);

        let vk_b = SigVerificationKey::try_from(vk1.clone()).unwrap();
        let vk2 = vk_b.try_into().unwrap();

        assert!(vk1 == vk2);
    }

    #[test]
    fn test_vk_encode_decode() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::Diversifier;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk1 = PublicKey::from_private(&sk, p_g, params);

        let vk_b = SigVerificationKey::try_from(vk1.clone()).unwrap();

        let encoded_vk = vk_b.encode();

        let decoded_vk = SigVerificationKey::decode(&mut encoded_vk.as_slice()).unwrap();
        assert_eq!(vk_b, decoded_vk);
    }
}
