// #![cfg_attr(not(feature = "std"), no_std)]
use runtime_support::{StorageValue, StorageMap, dispatch::Result};
use rstd::prelude::*;
use {balances, system::ensure_signed};

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

pub trait Trait: balances::Trait {
    // type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // fn deposit_event() = default;
        
        fn confidential_transfer (
            _origin,
        //     // zkproof: Proof<Bls12>,
        //     // cv_transfer: edwards::Point<Bls12, PrimeOrder>,
        //     // cv_balance: edwards::Point<Bls12, PrimeOrder>,
        //     // epk: edwards::Point<Bls12, PrimeOrder>,
        //     // rk: PublicKey<Bls12>,
        //     // sig_verifying_key: &PreparedVerifyingKey<Bls12>,
        //     // sighash_value: &[u8; 32],
        //     // auth_sig: RedjubjubSignature,
        //     // params: &JubjubBls12,
        )
        {
        //     // TODO: Elaborate Err message
        //     // ensure!(check_proof(
        //     //     zkproof,
        //     //     cv_transfer,
        //     //     cv_balance,
        //     //     epk,
        //     //     rk,
        //     //     sig_verifying_key,
        //     //     sighash_value,
        //     //     auth_sig,
        //     //     params
        //     // ), "The zkproof is invalid.");
            Ok(())
        }
    }
}

impl<T: Trait> Module<T> {}

// decl_storage! {
//     trait Store for Module<T: Trait> as ConfidentialTransfer {
//         pub CommittedBalance get(commited_balance): map PaymentAddress<Bls12> => edwards::Point<Bls12, PrimeOrder>;
//     }
// }
