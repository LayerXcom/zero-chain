use std::num::NonZeroU32;
use serde::{Deserialize, Serialize};
use super::error::Result;

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct Bytes(
    #[serde(with = "serde_bytes")]
    pub Vec<u8>
);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyFile {
    /// Keyfile UUID
    pub id: String,
    /// Keyfile version
    pub version: u32,
    /// Keyfile crypto
    pub crypto: Crypto,
    /// Optional address
    pub address: Option<Bytes>,
}


#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crypto {
    pub ciphertext: Bytes,
}

impl Crypto {
    pub fn encrypt(
        plain: &[u8],
        password: &[u8],
        iterations: u32,
    ) -> Result<Self>
    {
        unimplemented!();
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<Vec<u8>> {
        unimplemented!();
    }
}



fn kdf_iterations(
    password: &[u8],
    salt: &[u8],
    iterations: NonZeroU32
) -> (Vec<u8>, Vec<u8>)
{
    unimplemented!();
}
