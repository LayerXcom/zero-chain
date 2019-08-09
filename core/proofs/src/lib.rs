#[macro_use]
extern crate lazy_static;

use scrypto::jubjub::JubjubBls12;
use bellman::SynthesisError;
pub mod circuit;
pub mod prover;
pub mod keys;
pub mod elgamal;
pub mod transaction;
pub mod setup;
pub mod nonce;

pub use self::setup::setup;
pub use self::transaction::Transaction;
pub use self::keys::{EncryptionKey, ProofGenerationKey, SpendingKey, DecryptionKey};
pub use self::nonce::Nonce;

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
