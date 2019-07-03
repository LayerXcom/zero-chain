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
pub struct PreparedVk(Vec<u8>);

impl PreparedVk {
    pub fn into_prepared_vk(&self) -> Option<bellman_verifier::PreparedVerifyingKey<Bls12>> {
        bellman_verifier::PreparedVerifyingKey::<Bls12>::read(&mut &self.0[..]).ok()
    }

    pub fn from_prepared_vk(pvk: &bellman_verifier::PreparedVerifyingKey<Bls12>) -> Self {
        let mut writer = vec![];
        // let mut writer = vec![0u8; 41386]; // 41390
        #[cfg(feature = "std")]
        pvk.write(&mut &mut writer).unwrap();

        #[cfg(not(feature = "std"))]
        pvk.write(&mut &mut writer[..]).unwrap();

        PreparedVk(writer)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        PreparedVk(slice.to_vec())
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


#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use parity_codec::{Encode, Decode};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};

    fn get_pvk() -> PreparedVk {
        let vk_path = Path::new("../../zface/verification.params");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVk::from_slice(&buf_vk[..])
    }

    #[test]
    fn test_prepared_vk_rw() {
        let prepared_vk_vec = get_pvk().0;
        let prepared_vk = bellman_verifier::PreparedVerifyingKey::<Bls12>::read(&mut &prepared_vk_vec[..]).unwrap();

        let mut buf = vec![];
        prepared_vk.write(&mut &mut buf).unwrap();

        assert_eq!(buf, prepared_vk_vec);
    }

    #[test]
    fn test_pvk_encode_decode() {
        let pvk = get_pvk();
        let encoded_pvk = pvk.encode();
        let decoded_pvk = PreparedVk::decode(&mut encoded_pvk.as_slice()).unwrap();
        assert_eq!(pvk, decoded_pvk);
    }

    #[test]
    fn test_pvk_into_from() {
        let pvk = get_pvk();

        let into_pvk = pvk.into_prepared_vk().unwrap();
        let from_pvk = PreparedVk::from_prepared_vk(&into_pvk);

        assert_eq!(pvk, from_pvk);
    }
}
