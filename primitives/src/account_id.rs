use fixed_hash::construct_fixed_hash;
use crate::keys::PaymentAddress;

// FIXME
const SIZE: usize = 43;

construct_fixed_hash! {
    /// Fixed 344-bit hash.
    pub struct H344(SIZE);
}

pub type AccountId = H344;

impl codec::Encode for H344 {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl codec::Decode for H344 {
    fn decode<I: codec::Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as codec::Decode>::decode(input).map(H344)
    }
}

impl H344 {
    pub fn into_payment_address(&self) -> Option<PaymentAddress> {

    }
}

impl Into<AccountId> for PaymentAddress {
    
}