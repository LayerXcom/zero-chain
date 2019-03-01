#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core;

#[cfg(not(feature = "std"))]
mod std {
    pub use crate::core::*;
    pub use crate::alloc::vec;
    pub use crate::alloc::string;
    pub use crate::alloc::boxed;
    pub use crate::alloc::borrow;
}

extern crate parity_codec as codec;
extern crate parity_codec_derive as codec_derive;

pub mod keys;
pub mod account_id;
pub mod signature;
pub mod ciphertext;
pub mod proof;
pub mod public_key;

use lazy_static::lazy_static;
use jubjub::curve::JubjubBls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
