#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use ::core::*;
    pub use crate::alloc::vec;
    pub use crate::alloc::string;
    pub use crate::alloc::boxed;
    pub use crate::alloc::borrow;    
}

#[cfg(feature = "std")]
#[macro_use]
extern crate serde_derive;

pub mod pkd_address;
pub mod signature;
pub mod ciphertext;
pub mod proof;
pub mod sig_vk;
pub mod prepared_vk;
pub mod pvk;

use lazy_static::lazy_static;
use jubjub::curve::JubjubBls12;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
