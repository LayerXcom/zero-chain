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
use super::wallet::SerdeBytes;
use std::io::{self, Read, Write};
use std::convert::TryFrom;

mod constants;
mod components;
use constants::*;
pub use components::*;

pub trait Derivation: Sized {
    /// Master key generation:
    /// - Calculate I = BLAKE2b-512("MASTER_PERSONALIZATION", seed)
    /// - Split I into two 32-bytes arrays, I_L and I_R.
    /// - Use I_L as the master spending and I_R as the master chain code.
    fn master(seed: &[u8]) -> Self;

    /// Child key derivation:
    /// the method for deriving a child extended key, given a parent extended key and an index `i`,
    /// depends on the type of key being derived, and whether this is a hardened or non-hardened derivation.
    /// If an index `i` >= 2^31, the child is a hardended key. If not, the child is a non-hardened key.
    fn derive_child(&self, i: ChildIndex) -> io::Result<Self>;

    fn read<R: Read>(mut reader: R) -> io::Result<Self>;

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()>;
}

/// Extended spending key for HDKD
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

        let tag = EncKeyFingerPrint::try_from(&enc_key)?.tag();

        Ok(ExtendedSpendingKey {
            depth: self.depth + 1,
            parent_enckey_tag: tag,
            child_index: i,
            chain_code: ChainCode(right),
            spending_key: SpendingKey(fs),
        })
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let depth = reader.read_u8()?;
        let mut tag = [0u8; 4];
        reader.read_exact(&mut tag)?;

        let i = reader.read_u32::<LittleEndian>()?;
        let mut c = [0u8; 32];
        reader.read_exact(&mut c)?;
        let spending_key = SpendingKey::read(&mut reader)?;

        Ok(ExtendedSpendingKey {
            depth,
            parent_enckey_tag: EncKeyTag(tag),
            child_index: ChildIndex::from_index(i),
            chain_code: ChainCode(c),
            spending_key,
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.depth)?;
        writer.write_all(&self.parent_enckey_tag.0)?;
        writer.write_u32::<LittleEndian>(self.child_index.to_index())?;
        writer.write_all(&self.chain_code.0)?;
        writer.write_all(&self.spending_key.into_bytes()?)?;

        Ok(())
    }
}

/// Extended spending key for HDKD
pub struct ExtendedEncryptionKey {
    depth: u8,
    parent_enckey_tag: EncKeyTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub enc_key: EncryptionKey<Bls12>,
}

impl Derivation for ExtendedEncryptionKey {
    fn master(seed: &[u8]) -> Self {
        unimplemented!();
    }

    fn derive_child(&self, i: ChildIndex) -> io::Result<Self> {
        unimplemented!();
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let depth = reader.read_u8()?;
        let mut tag = [0u8; 4];
        reader.read_exact(&mut tag)?;

        let i = reader.read_u32::<LittleEndian>()?;
        let mut c = [0u8; 32];
        reader.read_exact(&mut c)?;

        let enc_key = EncryptionKey::read(&mut reader, &*PARAMS)?;

        Ok(ExtendedEncryptionKey {
            depth,
            parent_enckey_tag: EncKeyTag(tag),
            child_index: ChildIndex::from_index(i),
            chain_code: ChainCode(c),
            enc_key,
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.depth)?;
        writer.write_all(&self.parent_enckey_tag.0)?;
        writer.write_u32::<LittleEndian>(self.child_index.to_index())?;
        writer.write_all(&self.chain_code.0)?;
        writer.write_all(&self.enc_key.into_bytes()?)?;

        Ok(())
    }
}

impl TryFrom<ExtendedSpendingKey> for SerdeBytes {
    type Error = io::Error;

    fn try_from(xsk: ExtendedSpendingKey) -> io::Result<SerdeBytes> {
        let mut res = vec![];
        xsk.write(&mut res[..])?;

        Ok(SerdeBytes(res))
    }
}

/// Byte format of encryption key to implement SS58 trait.
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, Rng, XorShiftRng, Rand};

    #[test]
    fn derive_nonhardened_child() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();

        let xsk_master = ExtendedSpendingKey::master(&seed);

        let index_3 = ChildIndex::NonHardened(3);
        let xsk_child = xsk_master.derive_child(index_3);


    }

    #[test]
    fn derive_hardened_child() {

    }
}
