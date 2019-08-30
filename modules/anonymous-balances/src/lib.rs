//! A module for dealing with anonymous transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, Parameter};
use rstd::{
    prelude::*,
    result,
};
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
use zprimitives::{EncKey, Proof, Nonce, RightCiphertext, LeftCiphertext, Ciphertext};
use parity_codec::Codec;
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait + zk_system::Trait {
    // The overarching event type.
	// type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        pub fn anonymous_transfer(
            origin,
            zkproof: Proof,
            enc_keys: Vec<EncKey>,
            left_ciphertexts: Vec<LeftCiphertext>,
            right_ciphertexts: RightCiphertext,
            nonce: Nonce
        ) -> Result {
            let rvk = ensure_signed(origin)?;

            Ok(())
        }
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as AnonymousBalances {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map EncKey => Option<Ciphertext>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map EncKey => Option<Ciphertext>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map EncKey => Option<T::BlockNumber>;

    }
}

// decl_event! (
//     /// An event in this module.
//     pub enum Event<T> where <T as Trait>::AnonymousBalance {
//         AnonymousTransfer(AnonymousBalance),
//     }
// );

impl<T: Trait> Module<T> {
    // PUBLIC MUTABLES

    /// Rolling over allows us to send transactions asynchronously and protect from front-running attacks.
    /// We rollover an account in an epoch when the first message from this account is received;
    /// so, one message rolls over only one account.
    /// To achieve this, we define a separate (internal) method for rolling over,
    /// and the first thing every other method does is to call this method.
    /// More details in Section 3.1: https://crypto.stanford.edu/~buenz/papers/zether.pdf

    pub fn rollover(addr: &EncKey) -> result::Result<(), &'static str> {
        let current_epoch = <zk_system::Module<T>>::get_current_epoch();



        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

}
