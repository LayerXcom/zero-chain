use bellman::{
        groth16::{
            create_random_proof,
            verify_proof,
            Parameters,
            PreparedVerifyingKey,
            Proof,
        },
        SynthesisError,
};
use pairing::Field;
use rand::{Rand, Rng};
use scrypto::{
    jubjub::{
        JubjubEngine,
        FixedGenerators,
        edwards,
        PrimeOrder,
    },
    redjubjub::PublicKey,
};
use polkadot_rs::Api;
use zerochain_runtime::{UncheckedExtrinsic, Call, EncryptedBalancesCall, EncryptedAssetsCall};
use zprimitives::{
    EncKey as zEncKey,
    Ciphertext as zCiphertext,
    LeftCiphertext as zLeftCiphertext,
    RightCiphertext as zRightCiphertext,
    Nonce as zNonce,
    Proof as zProof
};
use crate::{
    circuit::ConfidentialTransfer,
    elgamal::Ciphertext,
    EncryptionKey,
    ProofGenerationKey,
    SpendingKey,
    KeyContext,
    ProofBuilder
};
use crate::crypto_components::{
    MultiEncKeys,
    MultiCiphertexts,
    Confidential,
    CiphertextTrait,
    PrivacyConfing,
    Submitter,
    Calls,
};
use std::{
    io::{self, Write, BufWriter},
    path::Path,
    fs::File,
    marker::PhantomData,
};

// impl<E: JubjubEngine> ProofBuilder<E> for KeyContext<E> {
//     type Submitter = AnonymousXt;
//     type PC = Anonymous;


// }


pub struct AnonymousXt {
    pub proof: [u8; 192],
}

impl Submitter for AnonymousXt {
    fn submit<R: Rng>(&self, calls: Calls, api: &Api, rng: &mut R) {
        unimplemented!();
    }
}
