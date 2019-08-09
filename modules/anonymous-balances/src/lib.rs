//! A module for dealing with anonymous transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, Parameter};
use rstd::prelude::*;
use rstd::result;
use bellman_verifier::verify_proof;
use pairing::{
    bls12_381::{
        Bls12,
        Fr,
    },
    Field,
};
use runtime_primitives::traits::{Member, Zero, MaybeSerializeDebug};
use jubjub::redjubjub::PublicKey;
use zprimitives::{
    EncKey,
    Proof,
    PreparedVk,
    ElgamalCiphertext,
    SigVk,
};
use parity_codec::Codec;
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait {
    /// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The units in which we record encrypted balances.
    type AnonymousBalance: ElgamalCiphertext + Parameter + Member + Default + MaybeSerializeDebug + Codec;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

    }
}

decl_storage! {
    trait Store for Module<T: Trait> as AnonymousBalances {

    }
}

decl_event! (
    /// An event in this module.
    pub enum Event<T> where <T as Trait>::AnonymousBalance {
        AnonymousTransfer(AnonymousBalance),
    }
);

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

}
 