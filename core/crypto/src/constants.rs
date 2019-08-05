/// The bytes size of plain text
pub const PLAINTEXT_SIZE: usize = 16;
/// The bytes size of cipher text
pub const CIPHERTEXT_SIZE: usize = 16;
// BLAKE2s invocation personalizations
pub const KDF_PERSONALIZATION: &'static [u8; 8] = b"zech_KDF";
pub const SIGHASH_PERSONALIZATION: &'static [u8; 16] = b"zech_sighash_per";
// BLAKE2s invocation personalizations
pub const CRH_IVK_PERSONALIZATION: &'static [u8; 8] = b"zech_ivk";
/// The constant personalization for elgamal extending function
pub const ELGAMAL_EXTEND_PERSONALIZATION: &'static [u8; 16] = b"zech_elgamal_ext";