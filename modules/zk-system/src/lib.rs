//! A module for dealing with zk-system
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, StorageValue};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::TryFrom;
use bellman_verifier::verify_proof;
use pairing::{
    bls12_381::{Bls12,Fr},
    Field,
};
use runtime_primitives::traits::As;
use jubjub::redjubjub::PublicKey;
use jubjub::curve::{edwards, PrimeOrder};
use zprimitives::{PreparedVk, Nonce, GEpoch, Proof, Ciphertext, LeftCiphertext, RightCiphertext, EncKey};
use keys::EncryptionKey;
use zcrypto::elgamal;

pub trait Trait: system::Trait {
	// The overarching event type.
	// type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin { }
}

decl_storage! {
    trait Store for Module<T: Trait> as ZkSystem {
        /// Global epoch length for rollover.
        /// The longer epoch length is, the longer rollover time is.
        /// This parameter should be fixed based on trade-off between UX and security in terms of front-running attacks.
        pub EpochLength get(epoch_length) config() : T::BlockNumber;

        /// A global last epoch which will be updated in the roll_over function.
        pub LastEpoch get(last_epoch) config() : T::BlockNumber;

        /// An epoch based generator point
        pub LastGEpoch get(g_epoch) build(|_| GEpoch::try_new().expect("Should init.")) : GEpoch;

        /// A nonce pool. All nonces are erasured at the time of starting each epochs.
        // Consider chainging Vec to BtreeMap
        pub NoncePool get(nonce_pool) config() : Vec<Nonce>;

        /// A verification key of zk proofs (only readable)
        pub VerifyingKey get(verifying_key) config(): PreparedVk;
    }
}

impl<T: Trait> Module<T> {

    /// Validate zk proofs of confidential transfers
	pub fn validate_confidential_proof (
        zkproof: &
        address_sender: &EncryptionKey<Bls12>,
        address_recipient: &EncryptionKey<Bls12>,
        amount_sender: &elgamal::Ciphertext<Bls12>,
        amount_recipient: &elgamal::Ciphertext<Bls12>,
        balance_sender: &elgamal::Ciphertext<Bls12>,
        rvk: &PublicKey<Bls12>,
        fee_sender: &elgamal::Ciphertext<Bls12>,
        nonce: &edwards::Point<Bls12, PrimeOrder>
    ) -> result::Result<bool, &'static str> {
        // Construct public input for circuit
        let mut public_input = [Fr::zero(); 22];

        {
            let (x, y) = address_sender.0.into_xy();
            public_input[0] = x;
            public_input[1] = y;
        }
        {
            let (x, y) = address_recipient.0.into_xy();
            public_input[2] = x;
            public_input[3] = y;
        }
        {
            let (x, y) = amount_sender.left.into_xy();
            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = amount_recipient.left.into_xy();
            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = amount_sender.right.into_xy();
            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = fee_sender.left.into_xy();
            public_input[10] = x;
            public_input[11] = y;
        }
        {
            let (x, y) = balance_sender.left.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = balance_sender.right.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }
        {
            let (x, y) = rvk.0.into_xy();
            public_input[16] = x;
            public_input[17] = y;
        }
        {
            let (x, y) = edwards::Point::<Bls12, PrimeOrder>::try_from(Self::g_epoch())
                .map_err(|_| "Failed to convert from GEpoch.")?
                .into_xy();

            public_input[18] = x;
            public_input[19] = y;
        }
        {
            let (x, y) = nonce.into_xy();
            public_input[20] = x;
            public_input[21] = y;
        }

        let pvk = Self::verifying_key().into_prepared_vk()
            .ok_or("Invalid verifying key.")?;

        // Verify the provided proof
        verify_proof(&pvk, &zkproof, &public_input[..])
            .map_err(|_| "Invalid proof.")
    }

    /// Get current epoch based on current block height.
    pub fn get_current_epoch() -> T::BlockNumber {
        let current_height = <system::Module<T>>::block_number();
        current_height / Self::epoch_length()
    }

    /// Initialize global nonce-related storages
    /// 1. Set last g_epoch to current g_epoch
    /// 2. Remove all nonces in the pool
    /// 3. Set last epoch to current epoch
    pub fn init_nonce_pool(current_epoch: T::BlockNumber) {
        if Self::last_epoch() < current_epoch {
            let g_epoch = GEpoch::group_hash(current_epoch.as_() as u32).unwrap();

            <LastGEpoch<T>>::put(g_epoch);
            <NoncePool<T>>::kill();
            <LastEpoch<T>>::put(current_epoch);
        }
    }
}
