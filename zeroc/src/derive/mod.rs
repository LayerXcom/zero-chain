// //! Implementation of "Hierarchical Deterministic Key Derivation" for Zerochain key components.
// //! It is respected to ZIP32 specification defined here https://github.com/zcash/zips/blob/master/zip-0032.rst.

use blake2_rfc::blake2b::Blake2b;
use proofs::keys::{ProofGenerationKey, SpendingKey, prf_expand_vec, prf_expand};
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
#[derive(Clone, Debug, PartialEq)]
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
        let proof_gen_key = ProofGenerationKey::from_spending_key(&self.spending_key, &PARAMS);

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
                    &[&[0x12], &proof_gen_key.into_bytes()?, &i_le],
                )
            }
        };

        let left = &hashed.as_bytes()[..32];
        let mut right = [0u8; 32];
        right.copy_from_slice(&hashed.as_bytes()[32..]);

        let tag = EncKeyFingerPrint::try_from(&proof_gen_key)?.tag();

        let mut fs = Fs::to_uniform(prf_expand(left, &[0x13]).as_bytes());
        fs.add_assign(&self.spending_key.0);

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

impl<'a> From<&'a ExtendedSpendingKey> for ExtendedProofGenerationKey {
    fn from(xsk: &ExtendedSpendingKey) -> Self {
        ExtendedProofGenerationKey {
            depth: xsk.depth,
            parent_enckey_tag: xsk.parent_enckey_tag,
            child_index: xsk.child_index,
            chain_code: xsk.chain_code,
            proof_gen_key: ProofGenerationKey::from_spending_key(&xsk.spending_key, &PARAMS),
        }
    }
}

/// Extended spending key for HDKD
#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedProofGenerationKey {
    depth: u8,
    parent_enckey_tag: EncKeyTag,
    child_index: ChildIndex,
    chain_code: ChainCode,
    pub proof_gen_key: ProofGenerationKey<Bls12>,
}

impl Derivation for ExtendedProofGenerationKey {
    fn master(seed: &[u8]) -> Self {
        let xsk_master = ExtendedSpendingKey::master(seed);
        ExtendedProofGenerationKey::from(&xsk_master)
    }

    fn derive_child(&self, i: ChildIndex) -> io::Result<Self> {
        let hashed = match i {
            ChildIndex::Hardened(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "Hardened key cannot be derived from `ExtendedProofGenerationKey`."))
            },
            ChildIndex::NonHardened(i) => {
                let mut i_le = [0u8; 4];
                LittleEndian::write_u32(&mut i_le, i);
                prf_expand_vec(
                    &self.chain_code.0,
                    &[&[0x12], &self.proof_gen_key.into_bytes()?, &i_le],
                )
            },
        };

        let left = &hashed.as_bytes()[..32];
        let mut right = [0u8; 32];
        right.copy_from_slice(&hashed.as_bytes()[32..]);

        let tag = EncKeyFingerPrint::try_from(&self.proof_gen_key)?.tag();

        let fs = Fs::to_uniform(prf_expand(left, &[0x13]).as_bytes());
        let proof_gen_key =
            ProofGenerationKey::from_spending_key(&SpendingKey(fs), &*PARAMS).add(&self.proof_gen_key, &*PARAMS);

        Ok(ExtendedProofGenerationKey {
            depth: self.depth + 1,
            parent_enckey_tag: tag,
            child_index: i,
            chain_code: ChainCode(right),
            proof_gen_key,
        })
    }

    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let depth = reader.read_u8()?;
        let mut tag = [0u8; 4];
        reader.read_exact(&mut tag)?;

        let i = reader.read_u32::<LittleEndian>()?;
        let mut c = [0u8; 32];
        reader.read_exact(&mut c)?;

        let proof_gen_key = ProofGenerationKey::read(&mut reader, &*PARAMS)?;

        Ok(ExtendedProofGenerationKey {
            depth,
            parent_enckey_tag: EncKeyTag(tag),
            child_index: ChildIndex::from_index(i),
            chain_code: ChainCode(c),
            proof_gen_key,
        })
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.depth)?;
        writer.write_all(&self.parent_enckey_tag.0)?;
        writer.write_u32::<LittleEndian>(self.child_index.to_index())?;
        writer.write_all(&self.chain_code.0)?;
        writer.write_all(&self.proof_gen_key.into_bytes()?)?;

        Ok(())
    }
}

impl TryFrom<&ExtendedSpendingKey> for Vec<u8> {
    type Error = io::Error;

    fn try_from(xsk: &ExtendedSpendingKey) -> io::Result<Vec<u8>> {
        let mut res = vec![];
        xsk.write(&mut res)?;

        Ok(res)
    }
}

impl TryFrom<ExtendedSpendingKey> for SerdeBytes {
    type Error = io::Error;

    fn try_from(xsk: ExtendedSpendingKey) -> io::Result<SerdeBytes> {
        let mut res = vec![];
        xsk.write(&mut res)?;

        Ok(SerdeBytes(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, Rng, XorShiftRng};

    fn gen_master_key_pairs() -> (ExtendedSpendingKey, ExtendedProofGenerationKey) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();

        let xsk_master = ExtendedSpendingKey::master(&seed);
        let xpgk_master = ExtendedProofGenerationKey::master(&seed);

        (xsk_master, xpgk_master)
    }

    #[test]
    fn derive_nonhardened_child() {
        let (xsk_m, xpgk_m) = gen_master_key_pairs();

        let index_3 = ChildIndex::NonHardened(3);
        let xsk_child = xsk_m.derive_child(index_3);
        let xpgk_child = xpgk_m.derive_child(index_3);

        assert!(xsk_child.is_ok());
        assert!(xpgk_child.is_ok());

        assert_eq!(
            ExtendedProofGenerationKey::from(&xsk_child.unwrap()),
            xpgk_child.unwrap()
        );
    }

    #[test]
    fn derive_hardened_child() {
        let (xsk_m, xpgk_m) = gen_master_key_pairs();
        let index_3 = ChildIndex::Hardened(3);
        let xsk_h3 = xsk_m.derive_child(index_3).unwrap();
        let xpgk_h3 = xpgk_m.derive_child(index_3);

        assert!(xpgk_h3.is_err());

        let xpgk_h3 = ExtendedProofGenerationKey::from(&xsk_h3);
        let index_5 = ChildIndex::NonHardened(5);
        let xsk_h3_n5 = xsk_h3.derive_child(index_5);
        let xpgk_h3_n5 = xpgk_h3.derive_child(index_5);

        assert!(xsk_h3_n5.is_ok());
        assert!(xpgk_h3_n5.is_ok());
        assert_eq!(
            ExtendedProofGenerationKey::try_from(&xsk_h3_n5.unwrap()).unwrap(),
            xpgk_h3_n5.unwrap(),
        );
    }

    #[test]
    fn read_write() {
        let (xsk_m, xpgk_m) = gen_master_key_pairs();

        let mut bytes = vec![];
        xsk_m.write(&mut bytes).unwrap();
        let xsk_m_read = ExtendedSpendingKey::read(&bytes[..]).unwrap();
        assert_eq!(xsk_m_read, xsk_m);

        let mut bytes = vec![];
        xpgk_m.write(&mut bytes).unwrap();
        let xsk_m_read = ExtendedProofGenerationKey::read(&bytes[..]).unwrap();
        assert_eq!(xsk_m_read, xpgk_m);
    }
}
