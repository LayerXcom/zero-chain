#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use self::core::*;
    pub use self::alloc::vec;
    pub use self::alloc::string;
    pub use self::alloc::boxed;
    pub use self::alloc::borrow;
}

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod jubjub;
pub mod group_hash;
pub mod constants;
pub mod redjubjub;
pub mod util;
