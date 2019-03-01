// //! A simple module for dealing with confidential transfer of fungible assets.

// // Ensure we're `no_std` when compiling for Wasm.
// #![cfg_attr(not(feature = "std"), no_std)]
// #![cfg_attr(not(feature = "std"), feature(alloc))]

// use runtime_support::{StorageValue, StorageMap, Parameter};
// use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, StaticLookup};
// use system::ensure_signed;

// use bellman_verifier::groth16::{   
//     PreparedVerifyingKey, 
//     verify_proof, 
//     Proof,      
// };
// use pairing::{
//     bls12_381::{
//         Bls12, 
//         Fr,         
//     },
//     Field,    
// };
// use jubjub::{    
//     curve::{
//         edwards,         
//         FixedGenerators, 
//         JubjubBls12, 
//         Unknown, 
//         PrimeOrder
//     },    
//     redjubjub::{        
//         PublicKey, 
//         Signature as RedjubjubSignature,        
//     },
// };

// use zprimitives::PaymentAddress;

// pub trait Trait: system::Trait {
// 	/// The units in which we record balances.
// 	type Balance: Member + Parameter + SimpleArithmetic + Default + Copy;
// }

// decl_module! {	
// 	pub struct Module<T: Trait> for enum Call where origin: T::Origin {		
// 		fn confidential_transfer(
//             _origin,
//             zkproof: Proof<Bls12>,
//             cv_transfer: edwards::Point<Bls12, PrimeOrder>,
//             cv_balance: edwards::Point<Bls12, PrimeOrder>,
//             epk: edwards::Point<Bls12, PrimeOrder>,
//             rk: PublicKey<Bls12>,
//             verifying_key: PreparedVerifyingKey<Bls12>, // TODO: Hardcoded on-chain
//             sighash_value: [u8; 32],
//             auth_sig: RedjubjubSignature,
//             params: JubjubBls12
//         ) {
// 			// let origin = ensure_signed(origin)?;

//             // Verify the auth_sig
//             ensure!(
//                 Self::verify_auth_sig(rk, auth_sig, &sighash_value, &params),
//                 "Invalid auth_sig"
//             );

//             // Verify the zk proof
//             ensure!(
//                 Self::check_proof(
//                     zkproof,
//                     cv_transfer,
//                     cv_balance,
//                     epk,
//                     rk,
//                     &verifying_key,
//                     &sighash_value,
//                     auth_sig,
//                     &params
//                 ),
//                 "Invalid zkproof"
//             );                        
			
//             // TODO: Add ensure!(find_group_hash() == g_d_sender);


// 		}		
// 	}
// }

// // decl_storage! {
// //     trait Store for Module<T: Trait> as ConfidentialTransfer {
// //         // The balances represented by pedersen commitment for hiding.
// //         pub CommittedBalance get(committed_balance) : map PaymentAddress<Bls12> => CommittedBalanceMap<Bls12>;    
// //         // Encrypted parameters of pedersen commitment to get thier own balances    
// //         pub Txo get(txo) : map PaymentAddress<Bls12> => TxoMap<Bls12>;           
// //     }
// // }

// impl<T: Trait> Module<T> {
//     // Public immutables

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

// 	pub fn check_proof (    
//         zkproof: Proof<Bls12>,
//         cv_transfer: edwards::Point<Bls12, PrimeOrder>,
//         cv_balance: edwards::Point<Bls12, PrimeOrder>,
//         epk: edwards::Point<Bls12, PrimeOrder>,
//         rk: PublicKey<Bls12>,
//         verifying_key: &PreparedVerifyingKey<Bls12>,
//         sighash_value: &[u8; 32],
//         auth_sig: RedjubjubSignature,
//         params: &JubjubBls12,
//     ) -> bool {
//         // Check the points are not small order
//         if Self::is_small_order(&cv_transfer, params) {
//             return false;
//         }
//         if Self::is_small_order(&cv_balance, params) {
//             return false;
//         }
//         if Self::is_small_order(&rk.0, params) {
//             return false;
//         }                

//         // Construct public input for circuit
//         let mut public_input = [Fr::zero(); 8];
//         {
//             let (x, y) = (&cv_balance).into_xy();
//             public_input[0] = x;
//             public_input[1] = y;
//         }
//         {
//             let (x, y) = (&cv_transfer).into_xy();
//             public_input[2] = x;
//             public_input[3] = y;
//         }
//         {
//             let (x, y) = epk.into_xy();
//             public_input[4] = x;
//             public_input[5] = y;
//         }
//         {
//             let (x, y) = rk.0.into_xy();
//             public_input[6] = x;
//             public_input[7] = y;
//         }

//         // Verify the proof
//         match verify_proof(verifying_key, &zkproof, &public_input[..]) {
//             // No error, and proof verification successful
//             Ok(true) => true,
//             _ => false,                
//         }
        
//     }

//     fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>, params: &JubjubBls12) -> bool {
//         p.double(params).double(params).double(params) == edwards::Point::zero()
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
// }
