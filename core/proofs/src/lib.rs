#[macro_use]
extern crate lazy_static;

use scrypto::jubjub::JubjubBls12;
use bellman::SynthesisError;
pub mod circuit;
pub mod prover;
pub mod no_std_aliases;
pub mod setup;
pub mod nonce;
pub mod crypto_components;

pub use self::prover::*;
pub use self::setup::setup;
pub use self::no_std_aliases::keys::{EncryptionKey, ProofGenerationKey, SpendingKey, DecryptionKey};
pub use self::no_std_aliases::elgamal;
pub use self::nonce::Nonce;
pub use self::crypto_components::*;

lazy_static! {
    pub static ref PARAMS: JubjubBls12 = { JubjubBls12::new() };
}

// TODO: This should probably be removed and we
// should use existing helper methods on `Option`
// for mapping with an error.
/// This basically is just an extension to `Option`
/// which allows for a convenient mapping to an
/// error on `None`.
trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing)
        }
    }
}
