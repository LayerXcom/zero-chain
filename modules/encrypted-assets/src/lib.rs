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
    SigVk,
};
use jubjub::redjubjub::PublicKey;
use keys::EncryptionKey;
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

struct TypedParams {
    zkproof: bellman_verifier::Proof<Bls12>,
    issuer: EncryptionKey<Bls12>,
    total: elgamal::Ciphertext<Bls12>,
    rvk: PublicKey<Bls12>,
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
            zkproof: Proof,
            issuer: PkdAddress,
            total: T::EncryptedBalance
        ) {
            let rvk = ensure_signed(origin)?;

            // Convert provided parametrs into typed ones.
            let typed = Self::into_types(
                &zkproof,
                &issuer,
                &total,
                &rvk,
            )
            .map_err(|_| "Failed to convert into types.")?;

            let zero = elgamal::Ciphertext::zero();

            // Verify the zk proof
            if !<encrypted_balances::Module<T>>::validate_proof(
                &typed.zkproof,
                &typed.issuer,
                &typed.issuer,
                &typed.total,
                &typed.total,
                &typed.total,
                &typed.rvk,
                &zero,
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            let id = Self::next_asset_id();
            <NextAssetId<T>>::mutate(|id| *id += One::one());
            <EncryptedBalance<T>>::insert((id, issuer.clone()), total.clone());
            <TotalSupply<T>>::insert(id, total.clone());

            Self::deposit_event(RawEvent::Issued(id, issuer, total));
        }

        /// Move some encrypted assets from one holder to another.
        fn confidential_transfer(
            origin,
            asset_id: T::AssetId,
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

            // Rollover and get sender's balance.
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            let typed_balance_sender = Self::rollover(&address_sender, asset_id)
                .map_err(|_| "Invalid ciphertext of sender balance.")?;

            // Rollover and get recipient's balance
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            let typed_balance_recipient = Self::rollover(&address_recipient, asset_id)
                .map_err(|_| "Invalid ciphertext of recipient balance.")?;

            // Verify the zk proof
            if !<encrypted_balances::Module<T>>::validate_proof(
                &typed.zkproof,
                &typed.address_sender,
                &typed.address_recipient,
                &typed.amount_sender,
                &typed.amount_recipient,
                &typed_balance_sender,
                &typed.rvk,
                &typed.fee_sender,
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            // Subtracting transferred amount and fee from the sender's encrypted balances.
            // This function causes a storage mutation.
            Self::sub_enc_balance(
                &address_sender,
                asset_id,
                &typed_balance_sender,
                &typed.amount_sender,
                &typed.fee_sender
            );

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(
                &address_recipient,
                asset_id,
                &typed_balance_recipient,
                &typed.amount_recipient
            );

            Self::deposit_event(
                RawEvent::ConfidentialAssetTransferred(
                    asset_id, zkproof, address_sender, address_recipient,
                    amount_sender, amount_recipient, fee_sender,
                    T::EncryptedBalance::from_ciphertext(&typed_balance_sender),
                    rvk
                )
            );
        }

        /// Destroy any encrypted assets of `id` owned by `owner`.
        fn destroy(
            origin,
            zkproof: Proof,
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
    pub enum Event<T>
    where
        <T as Trait>::AssetId,
        <T as encrypted_balances::Trait>::EncryptedBalance,
        <T as system::Trait>::AccountId
    {
        /// Some encrypted assets were issued.
        Issued(AssetId, PkdAddress, EncryptedBalance),
        /// Some encrypted assets were transferred.
        ConfidentialAssetTransferred(
            AssetId, Proof, PkdAddress, PkdAddress, EncryptedBalance,
            EncryptedBalance, EncryptedBalance, EncryptedBalance, AccountId
        ),
        /// Some encrypted assets were destroyed.
        Destroyed(AssetId, PkdAddress, EncryptedBalance),
        InvalidZkProof(),
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
        pub TransactionBaseFee get(transaction_base_fee) config() : map T::AssetId => FeeAmount;

        /// The next asset identifier up for grabs.
        pub NextAssetId get(next_asset_id): T::AssetId;

        /// The total unit supply of an asset.
        pub TotalSupply: map T::AssetId => T::EncryptedBalance;
    }
}

impl<T: Trait> Module<T> {
    // PRIVATE IMMUTABLES

    fn into_types(
        zkproof: &Proof,
        issuer: &PkdAddress,
        total: &T::EncryptedBalance,
        rvk: &T::AccountId
    ) -> result::Result<TypedParams, &'static str>
    {
        // Get zkproofs with the type
        let typed_zkproof = zkproof
            .into_proof()
            .ok_or("Invalid zkproof")?;

        let typed_issuer = issuer
            .into_encryption_key()
            .ok_or("Invalid issuer")?;

        let typed_total = total
            .into_ciphertext()
            .ok_or("Invalid total")?;

        let typed_rvk = rvk
            .into_verification_key()
            .ok_or("Invalid rvk")?;

        Ok(TypedParams {
            zkproof: typed_zkproof,
            issuer: typed_issuer,
            total: typed_total,
            rvk:typed_rvk,
        })
    }

    /// Get current epoch of specified asset id based on current block height.
    fn get_current_epoch(asset_id: T::AssetId) -> T::BlockNumber {
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

    // Subtracting transferred amount and fee from encrypted balances.
    pub fn sub_enc_balance(
        address: &PkdAddress,
        asset_id: T::AssetId,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>,
        typed_fee: &elgamal::Ciphertext<Bls12>
    ) {
        let amount_plus_fee = typed_amount.add_no_params(&typed_fee);

        <EncryptedBalance<T>>::mutate((asset_id, *address), |balance| {
            let new_balance = balance.clone().map(
                |_| T::EncryptedBalance::from_ciphertext(&typed_balance.sub_no_params(&amount_plus_fee)));
            *balance = new_balance
        });
    }

    /// Adding transferred amount to pending transfer.
    pub fn add_pending_transfer(
        address: &PkdAddress,
        asset_id: T::AssetId,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>
    ) {
        <PendingTransfer<T>>::mutate((asset_id, *address), |pending_transfer| {
            let new_pending_transfer = pending_transfer.clone().map_or(
                Some(T::EncryptedBalance::from_ciphertext(&typed_amount)),
                |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_amount)))
            );
            *pending_transfer = new_pending_transfer
        });
    }

}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use support::{impl_outer_origin, assert_ok};
    use primitives::{H256, Blake2Hasher};
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256, IdentityLookup},
        testing::{Digest, DigestItem, Header}
    };
    use zprimitives::{Ciphertext, SigVerificationKey};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
    use hex_literal::{hex, hex_impl};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;

    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Digest = Digest;
        type AccountId = SigVerificationKey;
        type SigVerificationKey = u64;
        type Lookup = IdentityLookup<SigVerificationKey>;
        type Header = Header;
        type Event = ();
        type Log = DigestItem;
    }

    impl encrypted_balances::Trait for Test {
        type Event = ();
        type EncryptedBalance = Ciphertext;
    }

    impl Trait for Test {
        type Event = ();
        type AssetId = u64;
    }

    type EncryptedAssets = Module<Test>;
}
