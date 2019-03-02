//! A simple module for dealing with confidential transfer of fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

use support::{decl_module, decl_storage, decl_event, StorageValue, StorageMap, dispatch::Result, ensure};
use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, StaticLookup};
use system::ensure_signed;

use bellman_verifier::{   
    PreparedVerifyingKey, 
    verify_proof,           
};
use pairing::{
    bls12_381::{
        Bls12, 
        Fr,         
    },
    Field,    
};
use jubjub::{    
    curve::{
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

use zprimitives::{
    account_id::AccountId, 
    ciphertext::Ciphertext, 
    proof::Proof, 
    public_key::SigVerificationKey, 
    signature::Signature,
    keys::{PaymentAddress},
    prepared_vk::PreparedVk,
};

use zcrypto::elgamal;

pub trait Trait: system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

// params: JubjubBls12  // TODO: Hardcoded on-chain

decl_module! {	
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {		
        // Initializing events
		// this is needed only if you are using events in your module
		fn deposit_event<T>() = default;

		pub fn confidential_transfer(
            _origin,
            zkproof: Proof,           
            address_sender: AccountId, // TODO: Extract from origin
            address_recipient: AccountId,
            value_sender: Ciphertext,
            value_recipient: Ciphertext,
            balance_sender: Ciphertext,          
            rk: SigVerificationKey                    
            // auth_sig: Signature,            
        ) -> Result {
			// let origin = ensure_signed(origin)?;

            // // Verify the auth_sig
            // ensure!(
            //     Self::verify_auth_sig(rk, auth_sig, &sighash_value, &params),
            //     "Invalid auth_sig"
            // );
            
            let szkproof = zkproof.into_proof().unwrap();
            let saddr_sender = address_sender.into_payment_address().unwrap();
            let saddr_recipient = address_recipient.into_payment_address().unwrap();
            let svalue_sender = value_sender.into_ciphertext().unwrap();
            let svalue_recipient = value_recipient.into_ciphertext().unwrap();
            let sbalance_sender = balance_sender.into_ciphertext().unwrap();
            let srk = rk.into_verification_key().unwrap();

            // Verify the zk proof
            ensure!(
                Self::check_proof(
                    szkproof,
                    saddr_sender,
                    saddr_recipient,
                    svalue_sender,
                    svalue_recipient,
                    sbalance_sender,
                    srk,                    
                ),
                "Invalid zkproof"
            );               

            Ok(())         			            
		}		
	}
}

decl_storage! {
    trait Store for Module<T: Trait> as ConfTransfer {
        // The encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) : map AccountId => Ciphertext;         
        pub VerifyingKey get(verifying_key) config(): PreparedVk; 
    }
}

decl_event! (
    /// An event in this module.
	pub enum Event<T> where AccountId = <T as system::Trait>::AccountId {
		// Just a dummy event.
		// Event `Something` is declared with a parameter of the type `u32` and `AccountId`
		// To emit this event, we call the deposit funtion, from our runtime funtions
		SomethingStored(u32, AccountId),
	}
);

impl<T: Trait> Module<T> {
    // Public immutables

//     pub fn verify_auth_sig (
//         rk: PublicKey<Bls12>, 
//         auth_sig: RedjubjubSignature,
//         sighash_value: &[u8; 32],
//         params: &JubjubBls12,
//     ) -> bool {        
//         // Compute the signature's message for rk/auth_sig
//         let mut data_to_be_signed = [0u8; 64];
//         rk.0.write(&mut data_to_be_signed[0..32])
//             .expect("message buffer should be 32 bytes");
//         (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash_value[..]);

//         // Verify the auth_sig
//         rk.verify(
//             &data_to_be_signed,
//             &auth_sig,
//             FixedGenerators::SpendingKeyGenerator,
//             &params,
//         )
//     }

	pub fn check_proof (    
        zkproof: bellman_verifier::Proof<Bls12>,
        address_sender: PaymentAddress<Bls12>,
        address_recipient: PaymentAddress<Bls12>,
        value_sender: elgamal::Ciphertext<Bls12>,
        value_recipient: elgamal::Ciphertext<Bls12>,
        balance_sender: elgamal::Ciphertext<Bls12>,
        rk: PublicKey<Bls12>,
        // verifying_key: &PreparedVerifyingKey<Bls12>,              
    ) -> bool {
        // Construct public input for circuit
        let mut public_input = [Fr::zero(); 16];

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
            let (x, y) = value_sender.left.into_xy();
            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = value_recipient.left.into_xy();
            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = value_sender.right.into_xy();
            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = balance_sender.left.into_xy();
            public_input[10] = x;
            public_input[11] = y;
        }
        {
            let (x, y) = balance_sender.right.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = rk.0.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }

        let pvk = Self::verifying_key().into_prepared_vk().unwrap();

        // Verify the proof
        match verify_proof(&pvk, &zkproof, &public_input[..]) {
            // No error, and proof verification successful
            Ok(true) => true,
            _ => false,                
        }
        
    }

    // fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>, params: &JubjubBls12) -> bool {
    //     p.double(params).double(params).double(params) == edwards::Point::zero()
    // }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
// }
