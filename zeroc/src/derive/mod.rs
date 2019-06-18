// //! Implementation of "Hierarchical Deterministic Key Derivation" for Zerochain key components.
// //! It is respected to ZIP32 specification defined here https://github.com/zcash/zips/blob/master/zip-0032.rst.

use parity_codec::{Encode, Decode};
use primitives::crypto::{Ss58Codec, Derive, DeriveJunction};
use blake2_rfc::blake2b::Blake2b;
use proofs::keys::{EncryptionKey, SpendingKey, prf_expand_vec, prf_expand};
use scrypto::jubjub::{JubjubEngine, fs::Fs, ToUniform};
use pairing::{bls12_381::Bls12, Field};
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use crate::PARAMS;
use std::io::{self, Read, Write};

mod constants;
use constants::*;

/// A 32-byte chain code
#[derive(Clone, Copy, Debug, PartialEq)]
struct ChainCode([u8; CHAIN_CODE_LENGTH]);

/// A encryption key fingerprint which is used to uniquely identify a particular EncryptionKey.
struct EncKeyFingerPrint([u8; FINGER_PRINT_LENGTH]);

impl<E: JubjubEngine> From<&EncryptionKey<E>> for EncKeyFingerPrint {
    fn from(enc_key: &EncryptionKey<E>) -> Self {
        let mut h = Blake2b::with_params(32, &[], &[], EKFP_PERSONALIZATION);
        let enc_key_bytes = enc_key.into_bytes()
            .expect("should be converted to bytes array.");
        h.update(&enc_key_bytes[..]);

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

impl ChildIndex {
    pub fn from_index(i: u32) -> Self {
        match i {
            n if n >= (1 << 31) => ChildIndex::Hardened(n - ( 1 << 31)),
            n => ChildIndex::NonHardened(n),
        }
    }

    fn master() -> Self {
        ChildIndex::from_index(0)
    }

    fn to_index(&self) -> u32 {
        match self {
            &ChildIndex::Hardened(i) => i + ( 1 << 31 ),
            &ChildIndex::NonHardened(i) => i,
        }
    }
}

pub trait Derivation: Sized {
    /// Master key generation
    /// - Calculate I = BLAKE2b-512("MASTER_PERSONALIZATION", seed)
    /// - Split I into two 32-bytes arrays, I_L and I_R.
    /// - Use I_L as the master spending and I_R as the master chain code.
    fn master(seed: &[u8]) -> Self;

    /// Child key derivation
    ///
    fn derive_child(&self, i: ChildIndex) -> io::Result<Self>;
    // fn read<R: Read>(mut reader: R) -> io::Result<Self>;
    // fn write<W: Write>(&self, mut writer: W) -> io::Result<()>;
}

pub struct ExtendedSpendingKey {
    depth: u8,
    parent_enckey_tag: EncKeyTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub spending_key: SpendingKey<Bls12>,
}

impl Derivation for ExtendedSpendingKey {
    fn master(seed: &[u8]) -> Self {
        let mut h = Blake2b::with_params(64, &[], &[], MASTER_PERSONALIZATION);
        h.update(seed);
        let hashed = h.finalize();

        let left = &hashed.as_bytes()[..32];
        let mut right = [0u8; 32];
        right.copy_from_slice(&hashed.as_bytes()[32..]);

        ExtendedSpendingKey {
            depth: 0,
            parent_enckey_tag: EncKeyTag::master(),
            child_index: ChildIndex::master(),
            chain_code: ChainCode(right),
            spending_key: SpendingKey::from_seed(left),
        }
    }

    fn derive_child(&self, i: ChildIndex) -> io::Result<Self> {
        let enc_key = EncryptionKey::from_spending_key(&self.spending_key, &PARAMS)?;

        let hashed = match i {
            ChildIndex::Hardened(i) => {
                let mut i_le = [0u8; 4];
                LittleEndian::write_u32(&mut i_le, i + (1 << 31));
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x11], &self.spending_key.into_bytes()?, &i_le],
                )
            },
            ChildIndex::NonHardened(i) => {
                let mut i_le = [0u8; 4];
                LittleEndian::write_u32(&mut i_le, i);
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x12], &enc_key.into_bytes()?, &i_le],
                )
            }
        };

        let left = &hashed.as_bytes()[..32];
        let mut right = [0u8; 32];
        right.copy_from_slice(&hashed.as_bytes()[32..]);

        let mut fs = Fs::to_uniform(prf_expand(left, &[0x13]).as_bytes());
        fs.add_assign(&self.spending_key.0);

        Ok(ExtendedSpendingKey {
            depth: self.depth + 1,
            parent_enckey_tag: EncKeyFingerPrint::from(&enc_key).tag(),
            child_index: i,
            chain_code: ChainCode(right),
            spending_key: SpendingKey(fs),
        })
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
