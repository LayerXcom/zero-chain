#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use crate::alloc::borrow;
    pub use crate::alloc::boxed;
    pub use crate::alloc::string;
    pub use crate::alloc::vec;
    pub use ::core::*;
}

#[cfg(feature = "std")]
#[macro_use]
extern crate serde_derive;

pub mod ciphertext;
pub mod enc_key;
pub mod g_epoch;
pub mod left_ciphertext;
pub mod nonce;
pub mod proof;
pub mod right_ciphertext;
pub mod sig_vk;
pub mod signature;

pub use self::ciphertext::Ciphertext;
pub use self::enc_key::EncKey;
pub use self::g_epoch::GEpoch;
pub use self::left_ciphertext::LeftCiphertext;
pub use self::nonce::Nonce;
pub use self::proof::Proof;
pub use self::right_ciphertext::RightCiphertext;
pub use self::sig_vk::{SigVerificationKey, SigVk};
pub use self::signature::RedjubjubSignature;

use jubjub::curve::{JubjubBls12, JubjubEngine};
use lazy_static::lazy_static;
use pairing::io;

lazy_static! {
    pub static ref PARAMS: JubjubBls12 = { JubjubBls12::new() };
}

pub trait IntoXY<E: JubjubEngine> {
    fn into_xy(&self) -> Result<(E::Fr, E::Fr), io::Error>;
}

// just for test utility
impl<E: JubjubEngine> IntoXY<E> for u64 {
    fn into_xy(&self) -> Result<(E::Fr, E::Fr), io::Error> {
        unimplemented!();
    }
}
