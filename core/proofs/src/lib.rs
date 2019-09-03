#[macro_use]
extern crate lazy_static;

use scrypto::jubjub::JubjubBls12;
use bellman::SynthesisError;
pub mod circuit;
pub mod confidential;
pub mod anonymous;
pub mod no_std_aliases;
pub mod setup;
pub mod crypto_components;
mod constants;

pub use self::setup::{confidential_setup, anonymous_setup};
pub use self::no_std_aliases::keys::{
    EncryptionKey, ProofGenerationKey,
    SpendingKey, DecryptionKey,
    prf_expand_vec, prf_expand
};
pub use self::no_std_aliases::elgamal;
pub use self::crypto_components::{MultiEncKeys, Confidential, KeyContext, ProofBuilder};

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
