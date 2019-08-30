//! A module for dealing with zk-system
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, StorageValue, ensure};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::TryFrom;
use bellman_verifier::{verify_proof, PreparedVerifyingKey};
use pairing::bls12_381::Bls12;
use runtime_primitives::traits::As;
use zprimitives::{
    Nonce, GEpoch, Proof, Ciphertext,
    LeftCiphertext, RightCiphertext, EncKey,
};
use self::input_builder::PublicInputBuilder;
mod input_builder;


pub trait Trait: system::Trait { }

const CONFIDENTIAL_INPUT_SIZE: usize = 22;
const ANONIMOUS_INPUT_SIZE: usize = 105;

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

        /// A verification key of zk proofs of confidential transfer(only readable)
        pub ConfidentialVk get(confidential_vk) config(): PreparedVerifyingKey<Bls12>;

        /// A verification key of zk proofs of anonymous transfer(only readable)
        pub AnonymousVk get(anonymous_vk) config(): PreparedVerifyingKey<Bls12>;
    }
}

impl<T: Trait> Module<T> {
    /// Verify zk proofs of confidential transfers
	pub fn verify_confidential_proof (
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
        let mut public_input = PublicInputBuilder::<Bls12>::new(CONFIDENTIAL_INPUT_SIZE);
        public_input.push(Some(address_sender))
            .map_err(|_| "Faild to get address_sender into xy.")?;

        public_input.push(Some(address_recipient))
            .map_err(|_| "Faild to get address_recipient into xy.")?;

        public_input.push(Some(amount_sender))
            .map_err(|_| "Faild to get amount_sender into xy.")?;

        public_input.push(Some(amount_recipient))
            .map_err(|_| "Faild to get amount_recipient into xy.")?;

        public_input.push(Some(randomness))
            .map_err(|_| "Faild to get randomness into xy.")?;

        public_input.push(Some(fee_sender))
            .map_err(|_| "Faild to get fee_sender into xy.")?;

        public_input.push(Some(balance_sender.left()))
            .map_err(|_| "Faild to get balance_sender's left into xy.")?;

        public_input.push(Some(balance_sender.right()))
            .map_err(|_| "Faild to get balance_sender's right into xy.")?;

        public_input.push(Some(rvk.clone()))
            .map_err(|_| "Faild to get rvk into xy.")?;

        public_input.push(Some(Self::g_epoch()))
            .map_err(|_| "Faild to get g_epoch into xy.")?;

        public_input.push(Some(nonce))
            .map_err(|_| "Faild to get nonce into xy.")?;

        ensure!(public_input.len() == CONFIDENTIAL_INPUT_SIZE, "Mismatch the length of public input.");

        let proof = bellman_verifier::Proof::<Bls12>::try_from(zkproof)
            .map_err(|_| "Faild to read zkproof.")?;

        // Verify the provided proof
        verify_proof(
            &Self::confidential_vk(),
            &proof,
            public_input.as_slice()
        )
        .map_err(|_| "Invalid proof.")
    }

    /// Verify zk proofs of anonymous transfers
	pub fn verify_anonymous_proof (
        zkproof: &Proof,
        enc_keys: &[EncKey],
        left_ciphertexts: &[LeftCiphertext],
        right_ciphertext: &RightCiphertext,
        enc_balances: &[Ciphertext],
        rvk: &T::AccountId,
        nonce: &Nonce
    ) -> result::Result<bool, &'static str> {
        // Construct public input for circuit
        let mut public_input = PublicInputBuilder::<Bls12>::new(ANONIMOUS_INPUT_SIZE);
        public_input.push(enc_keys)
            .map_err(|_| "Faild to get enc keys into xy.")?;

        public_input.push(left_ciphertexts)
            .map_err(|_| "Faild to get left ciphertexts into xy.")?;

        public_input.push(enc_balances.iter().map(|e| e.left()))
            .map_err(|_| "Faild to get left ciphertexts into xy.")?;

        public_input.push(enc_balances.iter().map(|e| e.right()))
            .map_err(|_| "Faild to get right ciphertexts into xy.")?;

        public_input.push(Some(right_ciphertext))
            .map_err(|_| "Faild to get right ciphertexts into xy.")?;

        public_input.push(Some(rvk.clone()))
            .map_err(|_| "Faild to get rvk into xy.")?;

        public_input.push(Some(Self::g_epoch()))
            .map_err(|_| "Faild to get g_epoch into xy.")?;

        public_input.push(Some(nonce))
            .map_err(|_| "Faild to get nonce into xy.")?;

        ensure!(public_input.len() == ANONIMOUS_INPUT_SIZE, "Mismatch the length of public input.");

        let proof = bellman_verifier::Proof::<Bls12>::try_from(zkproof)
            .map_err(|_| "Faild to read zkproof.")?;

        // Verify the provided proof
        verify_proof(
            &Self::anonymous_vk(),
            &proof,
            public_input.as_slice()
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
