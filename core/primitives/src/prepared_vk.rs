use pairing::bls12_381::Bls12;
use bellman_verifier;
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;

#[cfg(feature = "std")]
use ::std::{vec::Vec, fmt, write};
#[cfg(not(feature = "std"))]
use crate::std::{vec::Vec, fmt, write};

use parity_codec_derive::{Encode, Decode};

/// Prepared Verifying Key for SNARKs proofs
#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct PreparedVk(
    pub Vec<u8>
);

impl PreparedVk {
    pub fn into_prepared_vk(&self) -> Option<bellman_verifier::PreparedVerifyingKey<Bls12>> {   
        bellman_verifier::PreparedVerifyingKey::read(&mut &self.0[..]).ok()        
    }

    pub fn from_prepared_vk(pvk: &bellman_verifier::PreparedVerifyingKey<Bls12>) -> Self {
        // let mut writer = vec![];
        let mut writer = vec![0u8; 41386];
        pvk.write(&mut &mut writer[..]).unwrap();
        PreparedVk(writer.to_vec())
    }
}

impl Into<PreparedVk> for bellman_verifier::PreparedVerifyingKey<Bls12> {
    fn into(self) -> PreparedVk {
        PreparedVk::from_prepared_vk(&self)
    }
}

impl fmt::Display for PreparedVk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0 {
            write!(f, "{:02x}", i)?;
        }        
        Ok(())
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for PreparedVk {
    fn as_bytes_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}


#[cfg(test)]
mod tests {
    use super::*;       
    use parity_codec::{Encode, Decode};    

    #[test]
    fn test_pvk_encode_decode() {
        // let pvk_vec_u8: Vec<u8> = (&PVK).to_vec().into_iter().map(|e| e as u8).collect();        
        // let pvk = PreparedVk(pvk_vec_u8);
        // let encoded_pvk = pvk.encode();
        // let decoded_pvk = PreparedVk::decode(&mut encoded_pvk.as_slice()).unwrap();
        // assert_eq!(pvk, decoded_pvk);
    }

    // TODO
    #[test]
    fn test_pvk_into_from() {
        // let pvk_vec_u8: Vec<u8> = (&PVK).to_vec().into_iter().map(|e| e as u8).collect();        
        // let pvk = PreparedVk(pvk_vec_u8);
        // println!("pvk:{:?}", pvk);
        // let into_pvk = pvk.into_prepared_vk().unwrap();
        // let from_pvk = PreparedVk::from_prepared_vk(&into_pvk);
        
        // println!("from_pvk:{:?}", from_pvk);
                
        // assert_eq!(pvk, from_pvk);
    }
}
