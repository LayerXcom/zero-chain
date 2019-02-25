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
    use rand::{Rand, Rng, SeedableRng, XorShiftRng, OsRng};    
    use pairing::bls12_381::Bls12;
    use crate::keys::*;

    #[test]
    fn test_into_from() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed[..]);

        let ex_sk = ExpandedSpendingKey::<Bls12>::from_spending_key(&seed[..]);
        let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk, &JUBJUB);
        let diversifier = Diversifier::new::<Bls12>(&JUBJUB).unwrap();
        let addr1 = viewing_key.into_payment_address(diversifier, &JUBJUB).unwrap();

        let account_id = AccountId::from_payment_address(&addr1);
        println!("account_id: {:?}", account_id);
        let addr2 = account_id.into_payment_address().unwrap();
        assert!(addr1 == addr2);
    }
}
