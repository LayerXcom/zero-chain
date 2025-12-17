use fixed_hash::construct_fixed_hash;
use jubjub::redjubjub;
use pairing::{
    bls12_381::{Bls12, Fr},
    io
};
use crate::{PARAMS, IntoXY};
use core::convert::TryFrom;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct SigVerificationKey(SIZE);
}

impl_fixed_hash_codec!(SigVerificationKey, SIZE);

impl TryFrom<redjubjub::PublicKey<Bls12>> for SigVerificationKey {
    type Error = io::Error;

    fn try_from(vk: redjubjub::PublicKey<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        vk.write(&mut &mut writer[..]).unwrap();

        Ok(SigVerificationKey::from_slice(&writer))
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

pub trait SigVk { }
impl SigVk for SigVerificationKey { }
impl SigVk for &SigVerificationKey { }
impl SigVk for u64 { }

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use pairing::bls12_381::Bls12;
    use jubjub::curve::{FixedGenerators, JubjubBls12};
    use jubjub::redjubjub::PublicKey;
    use core::convert::TryInto;

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
