//! A module for dealing with encrypted fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure, Parameter};
use rstd::prelude::*;
use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, One, StaticLookup};
use zprimitives::{
    PkdAddress,
    Ciphertext,
    SigVerificationKey,
    ElgamalCiphertext,
};

/// The module configuration trait.
pub trait Trait: system::Trait {
    // /// The overarching event type.
    // type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The units in which we record encrypted balances.
    type EncryptedBalance: ElgamalCiphertext + Parameter + Member + Default;

    /// The arithmetic type of asset identifier.
    type AssetId: Parameter + SimpleArithmetic + Default + Copy;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // fn deposit_event<T>() = default;

        fn issue(origin, total: T::EncryptedBalance) {

            let id = Self::next_asset_id();
            // <NextAssetId<T>>::mutate(|id| *id += One::one());
            // <EncryptedBalances<T>>::insert((id, ))
        }

        fn transfer(origin,
            id: T::AssetId,
            target: PkdAddress,
            amount: T::EncryptedBalance
            ) {

        }

        fn destroy(origin, id: T::AssetId) {

        }

    }
}

// decl_event!(
//     pub enum Event<T>
//     where
//     {

//     }
// );

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedAssets {
        EncryptedBalances: map (T::AssetId, PkdAddress) => T::EncryptedBalance;
        NextAssetId get(next_asset_id): T::AssetId;
        TotalSupply: map T::AssetId => T::EncryptedBalance;
    }
}
