#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;
#[cfg(feature = "std")]
use ::std::{fmt, vec::Vec, write};
use bellman_verifier;
use core::convert::TryFrom;
use pairing::{bls12_381::Bls12, io};
use parity_codec::{Decode, Encode};
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;

#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Proof(Vec<u8>);

impl TryFrom<bellman_verifier::Proof<Bls12>> for Proof {
    type Error = io::Error;

    fn try_from(proof: bellman_verifier::Proof<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 192];
        proof.write(&mut &mut writer[..])?;

        Ok(Proof(writer.to_vec()))
    }
}

impl TryFrom<&bellman_verifier::Proof<Bls12>> for Proof {
    type Error = io::Error;

    fn try_from(proof: &bellman_verifier::Proof<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 192];
        proof.write(&mut &mut writer[..])?;

        Ok(Proof(writer.to_vec()))
    }
}

impl TryFrom<Proof> for bellman_verifier::Proof<Bls12> {
    type Error = io::Error;

    fn try_from(proof: Proof) -> Result<Self, io::Error> {
        bellman_verifier::Proof::<Bls12>::read(&proof.0[..])
    }
}

impl TryFrom<&Proof> for bellman_verifier::Proof<Bls12> {
    type Error = io::Error;

    fn try_from(proof: &Proof) -> Result<Self, io::Error> {
        bellman_verifier::Proof::<Bls12>::read(&proof.0[..])
    }
}

impl Proof {
    pub fn from_slice(slice: &[u8]) -> Self {
        Proof(slice.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for Proof {
    fn as_bytes_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::{hex, hex_impl};

    #[test]
    fn test_proof_into_from() {
        let proof: [u8; 192] = hex!("8e7b55a0a7bf1e34fc9a031a883dd1b3c7217a325388b0fe38acb8294632c63d14c95bb2d596a5bfd3b887211b1ba726949b91456d17d0648d2981c44b6e53636c98f155789b69b793b06be8f83a18120253ae004ff607eb396c8e5492325a4d02cd84adc379b91638e5a1a2cafcd25311e9efd082136eaa8f7a4e4eb8214d2ea08eae54a30508c176596746b0ada2218ebc3cb934504345f89c21e3d3c011196002ef65218989f6bfc1b7aa6a69be7d339d7d11b7a7c336cc836367e216ab54");
        let proof_a = Proof::from_slice(&proof[..]);

        let proof_v = bellman_verifier::Proof::<Bls12>::try_from(proof_a.clone()).unwrap();
        let proof_b = Proof::try_from(proof_v.clone()).unwrap();

        assert_eq!(proof_a, proof_b);
    }
}
