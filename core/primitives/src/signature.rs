#[cfg(feature = "std")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;
// use primitive_types::H512;
use jubjub::redjubjub;
use runtime_primitives::traits::{Verify, Lazy};
use fixed_hash::construct_fixed_hash;
use crate::sig_vk::SigVerificationKey;
use jubjub::curve::FixedGenerators;
use crate::JUBJUB;
#[cfg(feature = "std")]
use substrate_primitives::bytes;

use parity_codec::{Encode, Decode, Input};


// #[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
// #[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
// pub struct RedjubjubSignature(H512);

const SIZE: usize = 64;

construct_fixed_hash! {
    pub struct H512(SIZE);
}

pub type RedjubjubSignature = H512;

#[cfg(feature = "std")]
impl Serialize for H512 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> 
        where S: Serializer
    {
        bytes::serialize(&self.0, serializer)
    }
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for RedjubjubSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        bytes::deserialize_check_len(deserializer, bytes::ExpectedLen::Exact(SIZE))
            .map(|x| H512::from_slice(&x))
    }
}

impl Encode for RedjubjubSignature {
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.0.using_encoded(f)
    }
}

impl Decode for RedjubjubSignature {
    fn decode<I: Input>(input: &mut I) -> Option<Self> {
        <[u8; SIZE] as Decode>::decode(input).map(H512)
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for RedjubjubSignature {
    fn as_bytes_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl Verify for RedjubjubSignature {
    type Signer = SigVerificationKey;
    fn verify<L: Lazy<[u8]>>(&self, mut msg: L, signer: &Self::Signer) -> bool {
        let sig = match self.into_signature() {
            Some(s) => s,
            None => return false
        };

        let p_g = FixedGenerators::SpendingKeyGenerator;

        // Compute the signature's message for rk/auth_sig
        // let mut data_to_be_signed = [0u8; 64];
        // rk.0.write(&mut data_to_be_signed[0..32])
        //     .expect("message buffer should be 32 bytes");
        // (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

        match signer.into_verification_key() {
            Some(vk) => return vk.verify(msg.get(), &sig, p_g, &JUBJUB),
            None => return false
        }
        
    }
}

//    pub fn verify_auth_sig (
//         rk: PublicKey<Bls12>, 
//         auth_sig: RedjubjubSignature,
//         sighash_value: &[u8; 32],
//         params: &JubjubBls12,
//     ) -> bool {        
//         // Compute the signature's message for rk/auth_sig
//         let mut data_to_be_signed = [0u8; 64];
//         rk.0.write(&mut data_to_be_signed[0..32])
//             .expect("message buffer should be 32 bytes");
//         (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

//         // Verify the auth_sig
//         rk.verify(
//             &data_to_be_signed,
//             &auth_sig,
//             FixedGenerators::SpendingKeyGenerator,
//             &params,
//         )
//     } 

// impl From<H512> for RedjubjubSignature {
// 	fn from(h: H512) -> RedjubjubSignature {
// 		RedjubjubSignature(h)
// 	}
// }

impl RedjubjubSignature {
    pub fn into_signature(&self) -> Option<redjubjub::Signature> {   
        redjubjub::Signature::read(&self.0[..]).ok()        
    }

    pub fn from_signature(sig: &redjubjub::Signature) -> Self {
        let mut writer = [0u8; 64];
        sig.write(&mut writer[..]).unwrap();        
        H512::from_slice(&writer)
    }
}

impl Into<RedjubjubSignature> for redjubjub::Signature {
    fn into(self) -> RedjubjubSignature {
        RedjubjubSignature::from_signature(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};    
    use pairing::bls12_381::Bls12;
    use jubjub::curve::{FixedGenerators, JubjubBls12};
    use jubjub::redjubjub::PublicKey;    

    #[test]
    fn test_sig_into_from() {
        let mut rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk = PublicKey::from_private(&sk, p_g, params);

        let msg = b"Foo bar";
        let sig1 = sk.sign(msg, &mut rng, p_g, params);
        
        assert!(vk.verify(msg, &sig1, p_g, params));

        let sig_b = RedjubjubSignature::from_signature(&sig1);        
        let sig2 = sig_b.into_signature().unwrap();

        assert!(sig1 == sig2);
    }

    #[test]
    fn test_sig_encode_decode() {
        let mut rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::SpendingKeyGenerator;
        let params = &JubjubBls12::new();

        let sk = redjubjub::PrivateKey::<Bls12>(rng.gen());
        let vk = PublicKey::from_private(&sk, p_g, params);

        let msg = b"Foo bar";
        let sig1 = sk.sign(msg, &mut rng, p_g, params);
        
        assert!(vk.verify(msg, &sig1, p_g, params));
        let sig_b = RedjubjubSignature::from_signature(&sig1);
        
        let encoded_sig = sig_b.encode();        
        
        let decoded_sig = RedjubjubSignature::decode(&mut encoded_sig.as_slice()).unwrap();
        assert_eq!(sig_b, decoded_sig);
    }    
}
