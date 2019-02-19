#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
mod std {
    pub use crate::core::*;
    pub use crate::alloc::vec;
    pub use crate::alloc::string;
    pub use crate::alloc::boxed;
    pub use crate::alloc::borrow;
}

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod jubjub;
pub mod group_hash;
pub mod constants;
pub mod redjubjub;
pub mod util;
