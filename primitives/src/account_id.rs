use fixed_hash::construct_fixed_hash;
use crate::keys::PaymentAddress;
use lazy_static;
use jubjub::curve::JubjubBls12;

// FIXME
const SIZE: usize = 43;

construct_fixed_hash! {
    /// Fixed 344-bit hash.
    pub struct H344(SIZE);
}

lazy_static! {
    static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
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
        PaymentAddress.write(self.as_ref())
    }

    pub fn from_payment_address(bytes: &[u8]) -> Option<Self> {
        H344::from_slice(PaymentAddress.read(&JUBJUB))
    }
}

impl Into<AccountId> for PaymentAddress {
    fn into(self) -> PaymentAddress {
        AccountId::from_payment_address(self)
    }
}
