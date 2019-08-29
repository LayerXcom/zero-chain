//! A module for dealing with zk-system
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, StorageValue};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::TryFrom;
use bellman_verifier::{verify_proof, PreparedVerifyingKey};
use pairing::{
    bls12_381::{Bls12, Fr},
    Field,
};
use runtime_primitives::traits::As;
use zprimitives::{
    PreparedVk, Nonce, GEpoch, Proof, Ciphertext,
    LeftCiphertext, RightCiphertext, EncKey, IntoXY,
};

mod input_builder;

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
        pub VerifyingKey get(verifying_key) config(): PreparedVerifyingKey<Bls12>;
    }
}

impl<T: Trait> Module<T> {
    /// Validate zk proofs of confidential transfers
	pub fn validate_confidential_proof (
        zkproof: &Proof,
        address_sender: &EncKey,
        address_recipient: &EncKey,
        amount_sender: &LeftCiphertext,
        amount_recipient: &LeftCiphertext,
        balance_sender: &Ciphertext,
        rvk: &T::AccountId,
        fee_sender: &LeftCiphertext,
        randomness: &RightCiphertext,
        nonce: &Nonce
    ) -> result::Result<bool, &'static str> {
        // Construct public input for circuit
        let mut public_input = [Fr::zero(); 22];

        {
            let (x, y) = address_sender
                .into_xy()
                .map_err(|_| "Faild to get address_sender into xy.")?;

            public_input[0] = x;
            public_input[1] = y;
        }
        {
            let (x, y) = address_recipient
                .into_xy()
                .map_err(|_| "Faild to get address_recipient into xy.")?;

            public_input[2] = x;
            public_input[3] = y;
        }
        {
            let (x, y) = amount_sender
                .into_xy()
                .map_err(|_| "Faild to get amount_sender into xy.")?;

            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = amount_recipient
                .into_xy()
                .map_err(|_| "Faild to get amount_recipient into xy.")?;

            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = randomness
                .into_xy()
                .map_err(|_| "Faild to get randomness into xy.")?;

            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = fee_sender
                .into_xy()
                .map_err(|_| "Faild to get fee_sender into xy.")?;

            public_input[10] = x;
            public_input[11] = y;
        }
        {
            let (x, y) = balance_sender
                .into_xy_left()
                .map_err(|_| "Faild to get balance_sender's left into xy.")?;

            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = balance_sender
                .into_xy_right()
                .map_err(|_| "Faild to get balance_sender's right into xy.")?;

            public_input[14] = x;
            public_input[15] = y;
        }
        {
            let (x, y) = rvk
                .into_xy()
                .map_err(|_| "Faild to get rvk into xy.")?;

            public_input[16] = x;
            public_input[17] = y;
        }
        {
            let (x, y) = Self::g_epoch()
                .into_xy()
                .map_err(|_| "Faild to get g_epoch into xy.")?;

            public_input[18] = x;
            public_input[19] = y;
        }
        {
            let (x, y) = nonce
                .into_xy()
                .map_err(|_| "Faild to get nonce into xy.")?;

            public_input[20] = x;
            public_input[21] = y;
        }

        let pvk = Self::verifying_key();
        let proof = bellman_verifier::Proof::<Bls12>::try_from(zkproof)
            .map_err(|_| "Faild to read zkproof.")?;

        // Verify the provided proof
        verify_proof(
            &pvk,
            &proof,
            &public_input[..]
        )
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
