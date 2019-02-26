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
#[macro_use]
extern crate parity_codec_derive as codec_derive;
#[cfg(feature = "std")]
use serde_derive::{Serialize, Deserialize};

pub mod keys;
pub mod account_id;
pub mod signature;
pub mod ciphertext;
pub mod proof;
pub mod public_key;

use signature::*;
use keys::*;
use account_id::*;
use ciphertext::*;
use proof::*;
use public_key::*;

#[derive(Eq, PartialEq, Clone, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Transaction {
    pub sig: Signature,                   // 64 bytes
    pub sighash_value: [u8; 32],          // 32 bytes
    pub vk: SigVerificationKey,           // 32 bytes
    pub proof: Proof,                     // 192 bytes
    pub address_sender: AccountId,        // 43 bytes
    pub address_recipient: AccountId,     // 43 bytes
    pub ciphertext_sender: Ciphertext,    // 64 bytes
    pub ciphertext_recipient: Ciphertext, // 64 bytes
}
