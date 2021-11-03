#[macro_use]
extern crate lazy_static;

use bellman::SynthesisError;
use scrypto::jubjub::JubjubBls12;
pub mod anonymous;
pub mod circuit;
pub mod confidential;
pub mod constants;
pub mod crypto_components;
pub mod no_std_aliases;
pub mod setup;

pub use self::crypto_components::{Confidential, KeyContext, MultiEncKeys, ProofBuilder};
pub use self::no_std_aliases::elgamal;
pub use self::no_std_aliases::keys::{
    prf_expand, prf_expand_vec, DecryptionKey, EncryptionKey, ProofGenerationKey, SpendingKey,
};
pub use self::setup::{anonymous_setup, confidential_setup};

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
            None => Err(SynthesisError::AssignmentMissing),
        }
    }
}
