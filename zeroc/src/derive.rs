use parity_codec::{Encode, Decode};
use primitives::crypto::{Ss58Codec, Derive, DeriveJunction};

#[derive(Clone, Copy, Debug, PartialEq)]
struct ChainCode([u8; 32]);

// pub struct ExtendedSpendingKey<K> {
//     pub key: ,
//     pub chaincode: ChainCode,
// }





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
