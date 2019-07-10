//! A module for dealing with encrypted fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure, Parameter, StorageValue};
use rstd::prelude::*;
use rstd::result;
use parity_codec::Codec;
use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, One, StaticLookup, MaybeSerializeDebug};
use system::ensure_signed;
use zprimitives::{
    PkdAddress,
    Proof,
    Ciphertext,
    SigVerificationKey,
    ElgamalCiphertext,
};
use zcrypto::elgamal;
use pairing::bls12_381::Bls12;
use encrypted_balances;

/// The module configuration trait.
pub trait Trait: system::Trait + encrypted_balances::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The arithmetic type of asset identifier.
    type AssetId: Parameter + SimpleArithmetic + Default + Copy;
}

type FeeAmount = u32;

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event<T>() = default;

        /// Issue a new class of encrypted fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `issuer` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
        fn issue(
            origin,
            issuer: PkdAddress,
            total: T::EncryptedBalance
        ) {
            let origin = ensure_signed(origin)?;

            // TODO: Verifying zk proof

            let id = Self::next_asset_id();
            <NextAssetId<T>>::mutate(|id| *id += One::one());
            <EncryptedBalances<T>>::insert((id, issuer.clone()), total.clone());
            <TotalSupply<T>>::insert(id, total.clone());

            Self::deposit_event(RawEvent::Issued(id, issuer, total));
        }

        /// Move some encrypted assets from one holder to another.
        fn transfer(
            origin,
            id: T::AssetId,
            zkproof: Proof,
            address_sender: PkdAddress,
            address_recipient: PkdAddress,
            amount_sender: T::EncryptedBalance,
            amount_recipient: T::EncryptedBalance,
            fee_sender: T::EncryptedBalance
        ) {
            let rvk = ensure_signed(origin)?;

            let typed = <encrypted_balances::Module<T>>::into_types(
                &zkproof,
                &address_sender,
                &address_recipient,
                &amount_sender,
                &amount_recipient,
                &rvk,
                &fee_sender,
            )
            .map_err(|_| "Failed to convert into types.")?;



        }

        /// Destroy any encrypted assets of `id` owned by `owner`.
        fn destroy(
            origin,
            owner: PkdAddress,
            id: T::AssetId
        ) {
            let origin = ensure_signed(origin)?;

            // TODO: Verifying zk proof

            // let balance = <EncryptedBalances<T>>::take((id, owner.clone()));

            // Self::deposit_event(RawEvent::Destroyed(id, owner, balance));

        }

    }
}

decl_event!(
    pub enum Event<T> where <T as Trait>::AssetId, <T as encrypted_balances::Trait>::EncryptedBalance {
        /// Some encrypted assets were issued.
        Issued(AssetId, PkdAddress, EncryptedBalance),
        /// Some encrypted assets were destroyed.
        Destroyed(AssetId, PkdAddress, EncryptedBalance),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedAssets {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) : map (T::AssetId, PkdAddress) => Option<T::EncryptedBalance>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map (T::AssetId, PkdAddress) => Option<T::EncryptedBalance>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map (T::AssetId, PkdAddress) => Option<T::BlockNumber>;

        /// Global epoch length for rollover.
        /// The longer epoch length is, the longer rollover time is.
        /// This parameter should be fixed based on trade-off between UX and security in terms of front-running attacks.
        pub EpochLength get(epoch_length) config() : map T::AssetId => T::BlockNumber;

        /// A fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config(): FeeAmount;

        /// The next asset identifier up for grabs.
        pub NextAssetId get(next_asset_id): T::AssetId;

        /// The total unit supply of an asset.
        pub TotalSupply: map T::AssetId => T::EncryptedBalance;
    }
}

impl<T: Trait> Module<T> {
    // PUBLIC IMMUTABLES

    /// Get current epoch of specified asset id based on current block height.
    pub fn get_current_epoch(asset_id: T::AssetId) -> T::BlockNumber {
        let current_height = <system::Module<T>>::block_number();
        current_height / Self::epoch_length(asset_id)
    }

    // PUBLIC MUTABLES

    pub fn rollover(addr: &PkdAddress, asset_id: T::AssetId) -> result::Result<elgamal::Ciphertext<Bls12>, &'static str> {
        let current_epoch = Self::get_current_epoch(asset_id);
        let addr_id = (asset_id, *addr);
        let zero = elgamal::Ciphertext::zero();

        let last_rollover = match Self::last_rollover(addr_id) {
            Some(l) => l,
            None => T::BlockNumber::zero(),
        };

        let pending_transfer = Self::pending_transfer(addr_id);

        // Get balance with the type
        let typed_balance = match Self::encrypted_balance(addr_id) {
            Some(b) => b.into_ciphertext().ok_or("Invalid balance ciphertext")?,
            None => zero.clone(),
        };

        // Get balance with the type
        let typed_pending_transfer = match pending_transfer.clone() {
            Some(b) => b.into_ciphertext().ok_or("Invalid pending_transfer ciphertext")?,
            // If pending_transfer is `None`, just return zero value ciphertext.
            None => zero.clone(),
        };

        // Checks if the last roll over was in an older epoch.
        // If so, some storage changes are happend here.
        if last_rollover < current_epoch {
            // transfer balance from pending_transfer to actual balance
            <EncryptedBalance<T>>::mutate(addr_id, |balance| {
                let new_balance = balance.clone().map_or(
                    pending_transfer,
                    |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_pending_transfer)))
                );
                *balance = new_balance
            });

            // Reset pending_transfer.
            <PendingTransfer<T>>::remove(addr_id);

            // Set last rollover to current epoch.
            <LastRollOver<T>>::insert(addr_id, current_epoch);
        }

        let res_balance = match Self::encrypted_balance(addr_id) {
            Some(b) => b.into_ciphertext().ok_or("Invalid balance ciphertext")?,
            None => zero.clone(),
        };

        // return actual typed balance.
        Ok(res_balance)
    }

}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use support::{impl_outer_origin, assert_ok};

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;

    impl system::Trait for Test {

    }
}
