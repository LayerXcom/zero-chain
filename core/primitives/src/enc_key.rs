use crate::{IntoXY, PARAMS};
use core::convert::TryFrom;
use fixed_hash::construct_fixed_hash;
use keys::EncryptionKey;
use pairing::bls12_381::{Bls12, Fr};
use pairing::io;
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

pub type EncKey = H256;

#[cfg(feature = "std")]
impl Serialize for EncKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for EncKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| EncKey::from_slice(&x))
    }
}

impl Encode for EncKey {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for EncKey {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H256)
    }
}

impl TryFrom<EncryptionKey<Bls12>> for EncKey {
    type Error = io::Error;

    fn try_from(enc_key: EncryptionKey<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        enc_key.write(&mut writer[..])?;

        Ok(H256::from_slice(&writer))
    }
}

impl TryFrom<EncKey> for EncryptionKey<Bls12> {
    type Error = io::Error;

    fn try_from(enc_key: EncKey) -> Result<Self, io::Error> {
        EncryptionKey::<Bls12>::read(&mut &enc_key.0[..], &PARAMS)
    }
}

impl TryFrom<&EncKey> for EncryptionKey<Bls12> {
    type Error = io::Error;

    fn try_from(enc_key: &EncKey) -> Result<Self, io::Error> {
        EncryptionKey::<Bls12>::read(&mut &enc_key.0[..], &PARAMS)
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for EncKey {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl IntoXY<Bls12> for EncKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = EncryptionKey::<Bls12>::try_from(self)?.into_xy();

        Ok(point)
    }
}

impl IntoXY<Bls12> for &EncKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = EncryptionKey::<Bls12>::try_from(**self)?.into_xy();

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryInto;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_addr_into_from() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();

        let addr1 = EncryptionKey::<Bls12>::from_seed(&seed[..], &*PARAMS).unwrap();

        let account_id = EncKey::try_from(addr1.clone()).unwrap();
        let addr2 = account_id.try_into().unwrap();
        assert!(addr1 == addr2);
    }
}
