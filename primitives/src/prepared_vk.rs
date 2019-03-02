#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use fixed_hash::construct_fixed_hash;

#[cfg(feature = "std")]
use substrate_primitives::bytes;

use pairing::bls12_381::Bls12;
use bellman_verifier;



/// Prepared Verifying Key for SNARKs proofs
#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct PreparedVk(pub Vec<u8>);


// #[cfg(feature = "std")]
// impl Serialize for H256 {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> 
//         where S: Serializer
//     {
//         bytes::serialize(&self.0, serializer)
//     }
// }

// #[cfg(feature = "std")]
// impl<'de> Deserialize<'de> for H256 {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//         where D: Deserializer<'de>
//     {
//         bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
//             .map(|x| H256::from_slice(&x))
//     }
// }

// impl codec::Encode for H256 {
//     fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
//         self.0.using_encoded(f)
//     }
// }

// impl codec::Decode for H256 {
//     fn decode<I: codec::Input>(input: &mut I) -> Option<Self> {
//         <[u8; SIZE] as codec::Decode>::decode(input).map(H256)
//     }
// }

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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use rand::{Rng, SeedableRng, XorShiftRng};    
//     use pairing::bls12_381::Bls12;
//     use jubjub::curve::{FixedGenerators, JubjubBls12};
//     use jubjub::redjubjub::PublicKey;
//     use codec::{Encode, Decode};

//     #[test]
//     fn test_vk_into_from() {
//         let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
//         let p_g = FixedGenerators::SpendingKeyGenerator;
//         let params = &JubjubBls12::new();

//         let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
//         let vk1 = PublicKey::from_private(&sk, p_g, params);

//         let vk_b = SigVerificationKey::from_verification_key(&vk1);        
//         let vk2 = vk_b.into_verification_key().unwrap();

//         assert!(vk1 == vk2);
//     }

//     #[test]
//     fn test_vk_encode_decode() {
//         let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
//         let p_g = FixedGenerators::SpendingKeyGenerator;
//         let params = &JubjubBls12::new();

//         let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
//         let vk1 = PublicKey::from_private(&sk, p_g, params);

//         let vk_b = SigVerificationKey::from_verification_key(&vk1);                
        
//         let encoded_vk = vk_b.encode();        
        
//         let decoded_vk = SigVerificationKey::decode(&mut encoded_vk.as_slice()).unwrap();
//         assert_eq!(vk_b, decoded_vk);
//     }    
// }
