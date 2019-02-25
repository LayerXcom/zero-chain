#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use fixed_hash::construct_fixed_hash;
use pairing::bls12_381::Bls12;
use bellman_verifier;


#[cfg(feature = "std")]
use substrate_primitives::bytes;

const SIZE: usize = 128;

construct_fixed_hash! {    
    pub struct H1536(SIZE);
}

pub type Proof = H1536;

#[cfg(feature = "std")]
impl Serialize for H1536 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> 
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for H1536 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| H1536::from_slice(&x))
    }
}

impl codec::Encode for H1536 {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl codec::Decode for H1536 {
    fn decode<I: codec::Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as codec::Decode>::decode(input).map(H1536)
    }
}

impl H1536 {
    pub fn into_proof(&self) -> Option<bellman_verifier::Proof<Bls12>> {   
        bellman_verifier::Proof::<Bls12>::read(&self.0[..]).ok()        
    }

    pub fn from_proof(proof: &bellman_verifier::Proof<Bls12>) -> Self {
        let mut writer = [0u8; 192];
        proof.write(&mut &mut writer[..]).unwrap();
        H1536::from_slice(&writer)
    }
}

impl Into<Proof> for bellman_verifier::Proof<Bls12> {
    fn into(self) -> Proof {
        Proof::from_proof(&self)
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use rand::{Rng, SeedableRng, XorShiftRng};        
    // use jubjub::curve::{FixedGenerators, JubjubBls12};
    // use jubjub::redjubjub::PublicKey;
    // use codec::{Encode, Decode};
    // #[cfg(feature = "std")]
    // use ::std::num::Wrapping;
    // #[cfg(not(feature = "std"))]
    // use crate::std::num::Wrapping;
    // use bellman_verifier::tests::dummy_engine::{Fr, DummyEngine};

    // impl H1536 {
    //     pub fn test_into_proof(&self) -> Option<bellman_verifier::Proof<DummyEngine>> {   
    //         bellman_verifier::Proof::<DummyEngine>::read(&self.0[..]).ok()        
    //     }

    //     pub fn test_from_proof(proof: &bellman_verifier::Proof<DummyEngine>) -> Self {
    //         let mut writer = [0u8; 192];
    //         proof.write(&mut &mut writer[..]).unwrap();
    //         H1536::from_slice(&writer)
    //     }
    // }

    #[test]
    fn test_proof_into_from() {                
        // let mut rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // let proof1 = bellman_verifier::Proof::<DummyEngine> {
        //     a: Fr(Wrapping(3269)), 
        //     b: Fr(Wrapping(471)), 
        //     c: Fr(Wrapping(8383)),
        // };

        // let proof_b = Proof::test_from_proof(&proof1);
        // println!("proof_b: {:?}", proof_b);
        // let proof2 = proof_b.test_into_proof().unwrap();
        // assert!(proof1 == proof2);
    }    
}
