#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use fixed_hash::construct_fixed_hash;
use crate::keys::PaymentAddress;
use lazy_static::lazy_static;
use jubjub::curve::JubjubBls12;
use pairing::bls12_381::Bls12;

#[cfg(feature = "std")]
use substrate_primitives::bytes;

// FIXME
const SIZE: usize = 48;

construct_fixed_hash! {
    /// Fixed 384-bit hash.
    pub struct H384(SIZE);
}

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}

pub type AccountId = H384;

#[cfg(feature = "std")]
impl Serialize for H384 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> 
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for H384 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| H384::from_slice(&x))
    }
}

impl codec::Encode for H384 {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl codec::Decode for H384 {
    fn decode<I: codec::Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as codec::Decode>::decode(input).map(H384)
    }
}

impl H384 {
    pub fn into_payment_address(&self) -> Option<PaymentAddress<Bls12>> {         
        PaymentAddress::<Bls12>::read(&mut &self.0[..], &JUBJUB).ok()        
    }

    pub fn from_payment_address(address: &PaymentAddress<Bls12>) -> Self {
        let mut writer = [0u8; 48];
        address.write(&mut writer[..]).unwrap();
        H384::from_slice(&writer)
    }
}

impl Into<AccountId> for PaymentAddress<Bls12> {
    fn into(self) -> AccountId {
        AccountId::from_payment_address(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_from() {
        unimplemented!();
    }
}
