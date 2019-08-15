//! A module for dealing with zk-system
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageValue, StorageMap, dispatch::Result, Parameter};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::{TryFrom, TryInto};
use bellman_verifier::verify_proof;
use pairing::{
    bls12_381::{Bls12,Fr},
    Field,
};
use runtime_primitives::traits::{Member, Zero, MaybeSerializeDebug, As};
use jubjub::redjubjub::PublicKey;
use jubjub::curve::{edwards, PrimeOrder};
use zprimitives::{
    EncKey, Proof, PreparedVk, ElgamalCiphertext,
    SigVk, Nonce, GEpoch,
};
use parity_codec::Codec;
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait {
	/// The overarching event type.
	// type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

    }
}

decl_storage! {
    trait Store for Module<T: Trait> as ZkSystem {

    }
}

