use bellman::groth16::{
    create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof,
    prepare_verifying_key, generate_random_parameters,
};
use pairing::{
    bls12_381::{Bls12, Fr, FrRepr},
    Field, PrimeField, PrimeFieldRepr, Engine,
};
use scrypto::{    
    jubjub::{edwards, fs::Fs, FixedGenerators, JubjubBls12, Unknown, PrimeOrder},    
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use proofs::primitives::{Diversifier, PaymentAddress, ProofGenerationKey, ValueCommitment};


#[derive(Clone, Encode, Decode, Default)]
pub struct Transaction {
    // Length of the rest of the extrinsic, // 1-5 bytes
 	// Version information, // 1 byte
 	pub nonce: u32,
 	pub sig: Signature, // 64 bytes
 	pub sig_verifying_key: PublicKey<Bls12>, // rk 32bytes
 	pub proof: Proof<Bls12>, // 192 bytes
 	pub balance_commitment: ValueCommiement<Bls12>, // 32 bytes
 	pub transfer_commitment: ValueCommiement<Bls12>, // 32bytes
 	pub epk: edwards::Point<Bls12, PrimeOrder>, // 32 bytes
 	pub payment_address_s: PaymentAddress<Bls12>, // 11 + 32 bytes
 	pub payment_address_r: PaymentAddress<Bls12>, // 11 + 32 bytes
 	pub ciphertext: EncryptedCommitment, // 32 bytes?
}

