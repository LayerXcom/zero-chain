//! A module for dealing with encrypted fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use encrypted_balances;
use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure, Parameter, StorageValue};
use rstd::prelude::*;
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

/// The module configuration trait.
pub trait Trait: system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The units in which we record encrypted balances.
    type EncryptedBalance: ElgamalCiphertext + Parameter + Member + Default + MaybeSerializeDebug + Codec;

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
            let origin = ensure_signed(origin)?;


        }

        /// Destroy any encrypted assets of `id` owned by `owner`.
        fn destroy(
            origin,
            owner: PkdAddress,
            id: T::AssetId
        ) {
            let origin = ensure_signed(origin)?;

            // TODO: Verifying zk proof

            let balance = <EncryptedBalances<T>>::take((id, owner.clone()));

            Self::deposit_event(RawEvent::Destroyed(id, owner, balance));

        }

    }
}

decl_event!(
    pub enum Event<T> where <T as Trait>::AssetId, <T as Trait>::EncryptedBalance {
        /// Some encrypted assets were issued.
        Issued(AssetId, PkdAddress, EncryptedBalance),
        /// Some encrypted assets were destroyed.
        Destroyed(AssetId, PkdAddress, EncryptedBalance),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedAssets {
        /// An encrypted balance for each account
        pub EncryptedBalances: map (T::AssetId, PkdAddress) => T::EncryptedBalance;
        /// A pending transfer
        pub PendingTransfer: map (T::AssetId, PkdAddress) => T::EncryptedBalance;
        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map PkdAddress => Option<T::BlockNumber>;
        /// A fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config(): FeeAmount;
        /// The next asset identifier up for grabs.
        pub NextAssetId get(next_asset_id): T::AssetId;
        /// The total unit supply of an asset.
        pub TotalSupply: map T::AssetId => T::EncryptedBalance;
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
}
