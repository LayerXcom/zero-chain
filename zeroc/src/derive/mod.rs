//! Implementation of "Hierarchical Deterministic Key Derivation" for Zerochain key components.
//! It is respected to ZIP32 specification defined here https://github.com/zcash/zips/blob/master/zip-0032.rst.

use parity_codec::{Encode, Decode};
use primitives::crypto::{Ss58Codec, Derive, DeriveJunction};
use blake2_rfc::blake2b::Blake2b;
use proofs::keys::{EncryptionKey, SpendingKey, prf_expand_vec};
use scrypto::jubjub::JubjubEngine;
use pairing::bls12_381::Bls12;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use crate::JUBJUB;
use std::io::{self, Read, Write};

const EKFP_PERSONALIZATION: &'static [u8; 16] = b"ZerochainEFinger";
pub const CHAIN_CODE_LENGTH: usize = 32;
pub const FINGER_PRINT_LENGTH: usize = 32;
pub const TAG_KENGTH: usize = 4;

/// A 32-byte chain code
#[derive(Clone, Copy, Debug, PartialEq)]
struct ChainCode([u8; CHAIN_CODE_LENGTH]);

/// A encryption key fingerprint which is used to uniquely identify a particular EncryptionKey.
struct EncKeyFingerPrint([u8; FINGER_PRINT_LENGTH]);

impl<E: JubjubEngine> From<&EncryptionKey<E>> for EncKeyFingerPrint {
    fn from(enc_key: &EncryptionKey<E>) -> Self {
        let mut h = Blake2b::with_params(32, &[], &[], EKFP_PERSONALIZATION);
        h.update(&enc_key.into_bytes());

        let mut enckey_fp = [0u8; 32];
        enckey_fp.copy_from_slice(h.finalize().as_bytes());
        EncKeyFingerPrint(enckey_fp)
    }
}

impl EncKeyFingerPrint {
    fn tag(&self) -> EncKeyTag {
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&self.0[..4]);
        EncKeyTag(tag)
    }
}

/// A encryption key tag is the first 4 bytes of the corresponding Encryption key fingerprint.
/// It is intended for optimizing performance of key lookups,
/// and must not be assumed to uniquely identify a particulaqr key.
#[derive(Clone, Copy, Debug, PartialEq)]
struct EncKeyTag([u8; TAG_KENGTH]);

impl EncKeyTag {
    fn master() -> Self {
        EncKeyTag([0u8; 4])
    }
}

/// A child index for a derived key
pub enum ChildIndex {
    NonHardened(u32),

    Hardened(u32),
}

pub trait Derivation {
    pub fn master(seed: &[u8]) -> Self;
    pub fn derive_child(&self, i: ChildIndex) -> Self;
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self>;
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()>;
}

pub struct ExtendedSpendingKey {
    depth: u8,
    parent_enckey_tag: EncKeyTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub spending_key: SpendingKey<Bls12>,
}

impl Derivation for ExtendedSpendingKey {
    fn derive_child(i: ChildIndex) -> Self {
        let enc_key = EncryptionKey::from_spending_key(&self.spending_key, &JUBJUB);
        let tmp = match i {
            ChildIndex::Hardened(i) => {
                let mut i_le = [0u8; 4];
                LittleEndian::write_u32(&mut i_le, i + (1 << 31));
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x11], &self.spending_key.into_bytes(), &i_le],
                )
            },
            ChildIndex::NonHardened(i) => {
                let mut i_le = [0u8; 4];
                LittleEndian::write_u32(&mut i_le, i);
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x12], &enc_key.into_bytes(), &i_le],
                )
            }
        };

        ExtendedSpendingKey {
            depth: self.depth + 1,
            parent_enckey_tag: EncKeyFingerPrint::from(&enc_key).tag(),
            child_index: i,
            chain_code:
        }
    }
}

impl ExtendedSpendingKey {
    pub fn master(seed: &[u8]) -> Self {

    }
}


#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
pub struct EncryptionKeyBytes(pub [u8; 32]);

impl AsRef<EncryptionKeyBytes> for EncryptionKeyBytes {
    fn as_ref(&self) -> &EncryptionKeyBytes {
        &self
    }
}

impl AsRef<[u8]> for EncryptionKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for EncryptionKeyBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl Derive for EncryptionKeyBytes {
    /// Derive a child key from a series of given junctions.
	///
	/// `None` if there are any hard junctions in there.
    fn derive<Iter: Iterator<Item=DeriveJunction>>(&self, path: Iter) -> Option<EncryptionKeyBytes> {
        unimplemented!();
    }
}
