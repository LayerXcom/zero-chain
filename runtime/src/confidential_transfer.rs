//! A simple module for dealing with confidential transfer of fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
// #![cfg_attr(not(feature = "std"), no_std)]

use runtime_support::{StorageValue, StorageMap, Parameter};
use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, StaticLookup};
use system::ensure_signed;

use bellman::groth16::{   
    PreparedVerifyingKey, 
    verify_proof, 
    Proof,      
};
use pairing::{
    bls12_381::{
        Bls12, 
        Fr,         
    },
    Field,    
};
use scrypto::{    
    jubjub::{
        edwards,         
        FixedGenerators, 
        JubjubBls12, 
        Unknown, 
        PrimeOrder
    },    
    redjubjub::{        
        PublicKey, 
        Signature as RedjubjubSignature,
    },
};

use proofs::{verifier::check_proof, primitives::PaymentAddress};

pub trait Trait: system::Trait {
	/// The units in which we record balances.
	type Balance: Member + Parameter + SimpleArithmetic + Default + Copy;
}

type AssetId = u32;

decl_module! {	
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {		
		fn confidential_transfer(
            _origin,
            zkproof: Proof<Bls12>,
            cv_transfer: edwards::Point<Bls12, PrimeOrder>,
            cv_balance: edwards::Point<Bls12, PrimeOrder>,
            epk: edwards::Point<Bls12, PrimeOrder>,
            rk: PublicKey<Bls12>,
            sig_verifying_key: PreparedVerifyingKey<Bls12>,
            sighash_value: [u8; 32],
            auth_sig: RedjubjubSignature,
            params: JubjubBls12
        ) {
			// let origin = ensure_signed(origin)?;
            ensure!(
                check_proof(
                    zkproof,
                    cv_transfer,
                    cv_balance,
                    epk,
                    rk,
                    &sig_verifying_key,
                    &sighash_value,
                    auth_sig,
                    &params
                ),
                "Invalid zkproof"
            );
            
			
		}		
	}
}



impl<T: Trait> Module<T> {
	
}
