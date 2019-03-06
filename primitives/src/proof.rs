use pairing::bls12_381::Bls12;
use bellman_verifier;

#[cfg(feature = "std")]
use ::std::vec::Vec;
#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;

use parity_codec_derive::{Encode, Decode};

#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Proof(pub Vec<u8>);

impl Proof {
    pub fn into_proof(&self) -> Option<bellman_verifier::Proof<Bls12>> {          
        bellman_verifier::Proof::<Bls12>::read(&self.0[..]).ok()        
    }

    pub fn from_proof(proof: &bellman_verifier::Proof<Bls12>) -> Self {
        let mut writer = [0u8; 192];        
        proof.write(&mut &mut writer[..]).unwrap();        
        Proof(writer.to_vec())  
    }
}

impl Into<Proof> for bellman_verifier::Proof<Bls12> {
    fn into(self) -> Proof {
        Proof::from_proof(&self)
    }
}
