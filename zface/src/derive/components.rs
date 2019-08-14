use blake2_rfc::blake2b::Blake2b;
use super::constants::*;
use proofs::ProofGenerationKey;
use scrypto::jubjub::JubjubEngine;
use std::convert::TryFrom;
use std::io;

/// A 32-byte chain code
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct ChainCode(pub(super) [u8; CHAIN_CODE_LENGTH]);

/// A proof generation key fingerprint which is used to uniquely identify a particular ProofGenerationKey.
pub(super) struct EncKeyFingerPrint([u8; FINGER_PRINT_LENGTH]);

impl<E: JubjubEngine> TryFrom<&ProofGenerationKey<E>> for EncKeyFingerPrint {
    type Error = io::Error;

    fn try_from(proof_gen_key: &ProofGenerationKey<E>) -> io::Result<Self> {
        let mut h = Blake2b::with_params(32, &[], &[], EKFP_PERSONALIZATION);
        let proof_gen_key_bytes = proof_gen_key.into_bytes()?;
        h.update(&proof_gen_key_bytes[..]);

        let mut enckey_fp = [0u8; 32];
        enckey_fp.copy_from_slice(h.finalize().as_bytes());

        Ok(EncKeyFingerPrint(enckey_fp))
    }
}

impl EncKeyFingerPrint {
    pub(super) fn tag(&self) -> EncKeyTag {
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&self.0[..4]);
        EncKeyTag(tag)
    }
}

/// A encryption key tag is the first 4 bytes of the corresponding Encryption key fingerprint.
/// It is intended for optimizing performance of key lookups,
/// and must not be assumed to uniquely identify a particulaqr key.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct EncKeyTag(pub(super) [u8; TAG_LENGTH]);

impl EncKeyTag {
    pub(super) fn master() -> Self {
        EncKeyTag([0u8; 4])
    }
}

/// A child index for a derived key
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChildIndex {
    NonHardened(u32),
    Hardened(u32),
}

impl ChildIndex {
    pub fn from_index(i: u32) -> Self {
        match i {
            n if n >= (1 << 31) => ChildIndex::Hardened(n - ( 1 << 31)),
            n => ChildIndex::NonHardened(n),
        }
    }

    pub(super) fn master() -> Self {
        ChildIndex::from_index(0)
    }

    pub(super) fn to_index(&self) -> u32 {
        match self {
            &ChildIndex::Hardened(i) => i + ( 1 << 31 ),
            &ChildIndex::NonHardened(i) => i,
        }
    }
}
