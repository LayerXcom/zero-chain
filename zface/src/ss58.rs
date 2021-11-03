use crate::derive::ExtendedSpendingKey;
use parity_codec::{Decode, Encode};
use primitives::crypto::{Derive, DeriveJunction, Ss58Codec};
use proofs::{EncryptionKey, PARAMS};
use std::{convert::TryFrom, io};

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
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        _path: Iter,
    ) -> Option<EncryptionKeyBytes> {
        unimplemented!();
    }
}

impl TryFrom<&ExtendedSpendingKey> for EncryptionKeyBytes {
    type Error = io::Error;

    fn try_from(xsk: &ExtendedSpendingKey) -> io::Result<Self> {
        let sk = xsk.spending_key;
        let enc_key = EncryptionKey::from_spending_key(&sk, &PARAMS)?;
        let mut ek_buf = [0u8; 32];
        enc_key.write(&mut ek_buf[..])?;

        Ok(EncryptionKeyBytes(ek_buf))
    }
}

impl TryFrom<&ExtendedSpendingKey> for String {
    type Error = io::Error;

    fn try_from(xsk: &ExtendedSpendingKey) -> io::Result<String> {
        let enc_key_bytes = EncryptionKeyBytes::try_from(xsk)?;
        Ok(enc_key_bytes.to_ss58check())
    }
}
