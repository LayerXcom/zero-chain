//! A module for dealing with anonymous transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure};
use rstd::{
    prelude::*,
    result,
};
use runtime_primitives::traits::Zero;
use zprimitives::{EncKey, Proof, Nonce, RightCiphertext, LeftCiphertext, Ciphertext};
use system::ensure_signed;

pub trait Trait: system::Trait + zk_system::Trait + encrypted_balances::Trait {
    // The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initializing events
		fn deposit_event<T>() = default;

        pub fn anonymous_transfer(
            origin,
            zkproof: Proof,
            enc_keys: Vec<EncKey>,
            left_ciphertexts: Vec<LeftCiphertext>,
            right_ciphertext: RightCiphertext,
            nonce: Nonce
        ) -> Result {
            ensure!(enc_keys.len() == left_ciphertexts.len(), "length should be equal");
            let rvk = ensure_signed(origin)?;

            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            for e in &enc_keys {
                Self::rollover(e)?;
            }

            // Veridate the provided nonce isn't included in the nonce pool.
            assert!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce));

            let mut acc = vec![];
            for c in &enc_keys {
                let tmp = Self::encrypted_balance(c).map_or(Ciphertext::zero(), |e| e);
                acc.push(tmp);
            }

            // Verify the zk proof
            if !<zk_system::Module<T>>::verify_anonymous_proof(
                    &zkproof,
                    &enc_keys[..],
                    &left_ciphertexts[..],
                    &right_ciphertext,
                    &acc[..],
                    &rvk,
                    &nonce
                )? {
                    Self::deposit_event(RawEvent::InvalidZkProof());
                    return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            for (e, c) in enc_keys.iter().zip(left_ciphertexts.iter()) {
                <encrypted_balances::Module<T>>::add_pending_transfer(e, c, &right_ciphertext)?;
            }

            Self::deposit_event(
                RawEvent::AnonymousTransfer(
                    zkproof,
                    enc_keys,
                    left_ciphertexts,
                    right_ciphertext,
                    rvk
                )
            );

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

decl_event! (
    /// An event in this module.
    pub enum Event<T> where <T as system::Trait>::AccountId {
        AnonymousTransfer(Proof, Vec<EncKey>, Vec<LeftCiphertext>, RightCiphertext, AccountId),
        InvalidZkProof(),
    }
);

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

        let last_rollover = Self::last_rollover(addr)
            .map_or(T::BlockNumber::zero(), |e| e);

        // Get balance with the type
        let enc_pending_transfer = Self::pending_transfer(addr)
            .map_or(Ciphertext::zero(), |e| e);

        // Checks if the last roll over was in an older epoch.
        // If so, some storage changes are happend here.
        if last_rollover < current_epoch {
            // transfer balance from pending_transfer to actual balance
            <EncryptedBalance<T>>::mutate(addr, |balance| {
                let new_balance = match balance.clone() {
                    Some(b) => b.add(&enc_pending_transfer),
                    None => Ok(enc_pending_transfer),
                };

                match new_balance {
                    Ok(nb) => *balance = Some(nb),
                    Err(_) => return Err("Faild to mutate encrypted balance."),
                }

                Ok(())
            })?;

            // Reset pending_transfer.
            <PendingTransfer<T>>::remove(addr);
            // Set last rollover to current epoch.
            <LastRollOver<T>>::insert(addr, current_epoch);
        }
        // Initialize a nonce pool
        <zk_system::Module<T>>::init_nonce_pool(current_epoch);

        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

}
