extern crate bellman;
extern crate byteorder;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;

use bellman::groth16::{
    crate_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof,
};
use byteorder::{LittleEndian, ReadBytesExt};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr,
};
use rand::{OsRng, Rand};
use sapling_crypto::{
    circuit::{
        multipack,
        sapling::{Output, Spend, TREE_DEPTH},
    },
    jubjub::{edwards, fs::Fs, FixedGenerators, JubjubBls12, Unknown},
    primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, ValueCommitment},
    redjubjub::{PrivateKey, PublicKey, Signature},
};

pub struct ProvingContext {
    bsk: Fs,
    bvk: edwards::Point<Bls12, Unknown>,
}

