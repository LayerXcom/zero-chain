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

pub mod elgamal;
