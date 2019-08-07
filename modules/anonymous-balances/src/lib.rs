//! A module for dealing with anonymous transfer
#![cfg_attr(not(feature = "std"), no_std)]

use rstd::prelude::*;
use rstd::result;
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
use zprimitives::{
    EncKey,
    Proof,
    PreparedVk,
    ElgamalCiphertext,
    SigVk,
};
use parity_codec::Codec;
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};
