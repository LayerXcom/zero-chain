/// The size of value
pub const V_SIZE = 8;
/// The size of random commitment
pub const R_SIZE = 32;
/// The size of plain text
pub const PLAINTEXT_SIZE = V_SIZE + R_SIZE;
/// The size of cipher text
pub const CIPHERTEXT_SIZE = V_SIZE + R_SIZE;
// BLAKE2s invocation personalizations
/// BLAKE2s Personalization for CRH^ivk = BLAKE2s(ak | nk)
pub const KDF_PERSONALIZATION: &'static [u8; 8]
          = b"zech_KDF";
