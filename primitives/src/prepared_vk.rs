use pairing::bls12_381::Bls12;
use bellman_verifier;

#[cfg(feature = "std")]
use ::std::vec::Vec;
#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;

/// Prepared Verifying Key for SNARKs proofs
#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct PreparedVk(pub Vec<u8>);

impl PreparedVk {
    pub fn into_prepared_vk(&self) -> Option<bellman_verifier::PreparedVerifyingKey<Bls12>> {   
        bellman_verifier::PreparedVerifyingKey::read(&mut &self.0[..]).ok()        
    }

    pub fn from_prepared_vk(pvk: &bellman_verifier::PreparedVerifyingKey<Bls12>) -> Self {
        let mut writer = vec![];
        pvk.write(&mut &mut writer[..]).unwrap();
        PreparedVk(writer)
    }
}

impl Into<PreparedVk> for bellman_verifier::PreparedVerifyingKey<Bls12> {
    fn into(self) -> PreparedVk {
        PreparedVk::from_prepared_vk(&self)
    }
}
