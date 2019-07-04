#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use fixed_hash::construct_fixed_hash;
use jubjub::curve::JubjubBls12;
use jubjub::redjubjub;
use crate::PARAMS;
use pairing::bls12_381::Bls12;

#[cfg(feature = "std")]
use substrate_primitives::bytes;
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct H256(SIZE);
}

pub type SigVerificationKey = H256;

use parity_codec::{Encode, Decode, Input};

#[cfg(feature = "std")]
impl Serialize for SigVerificationKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for SigVerificationKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
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

pub trait SigVk {
    fn into_verification_key(&self) -> Option<redjubjub::PublicKey<Bls12>>;
    fn from_verification_key(vk: &redjubjub::PublicKey<Bls12>) -> Self;
}

impl SigVk for SigVerificationKey {
    fn into_verification_key(&self) -> Option<redjubjub::PublicKey<Bls12>> {
        redjubjub::PublicKey::read(&mut &self.0[..], &PARAMS as &JubjubBls12).ok()
    }

    fn from_verification_key(vk: &redjubjub::PublicKey<Bls12>) -> Self {
        let mut writer = [0u8; 32];
        vk.write(&mut &mut writer[..]).unwrap();
        H256::from_slice(&writer)
    }
}

impl Into<SigVerificationKey> for redjubjub::PublicKey<Bls12> {
    fn into(self) -> SigVerificationKey {
        SigVerificationKey::from_verification_key(&self)
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for SigVerificationKey {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use pairing::bls12_381::Bls12;
    use jubjub::curve::{FixedGenerators, JubjubBls12};
    use jubjub::redjubjub::PublicKey;

    #[test]
    fn test_vk_into_from() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::Diversifier;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk1 = PublicKey::from_private(&sk, p_g, params);

        let vk_b = SigVerificationKey::from_verification_key(&vk1);
        let vk2 = vk_b.into_verification_key().unwrap();

        assert!(vk1 == vk2);
    }

    #[test]
    fn test_vk_encode_decode() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::Diversifier;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk1 = PublicKey::from_private(&sk, p_g, params);

        let vk_b = SigVerificationKey::from_verification_key(&vk1);

        let encoded_vk = vk_b.encode();

        let decoded_vk = SigVerificationKey::decode(&mut encoded_vk.as_slice()).unwrap();
        assert_eq!(vk_b, decoded_vk);
    }
}
