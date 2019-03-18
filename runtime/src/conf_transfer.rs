//! A simple module for dealing with confidential transfer of fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure};
use rstd::prelude::*;
use bellman_verifier::{    
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
        redjubjub::{        
            PublicKey,             
        },
    };

use zprimitives::{
    pkd_address::PkdAddress, 
    ciphertext::Ciphertext, 
    proof::Proof, 
    sig_vk::SigVerificationKey,      
    prepared_vk::PreparedVk,
};
use keys::PaymentAddress;
use zcrypto::elgamal;
use runtime_io;


pub trait Trait: system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;       
}

decl_module! {	
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {		
        // Initializing events
		// this is needed only if you are using events in your module
		fn deposit_event<T>() = default;

		pub fn confidential_transfer(
            _origin,
            zkproof: Proof,
            address_sender: PkdAddress, 
            address_recipient: PkdAddress,
            value_sender: Ciphertext,
            value_recipient: Ciphertext,
            balance_sender: Ciphertext,       
            rk: SigVerificationKey  // TODO: Extract from origin            
        ) -> Result {
            // Temporally removed the signature verification.
			// let rk = ensure_signed(origin)?;            
            
            // Get zkproofs with the type
            let szkproof = match zkproof.into_proof() {
                Some(v) => v,
                None => return Err("Invalid zkproof"),
            };

            // Get address_sender with the type
            let saddr_sender = match address_sender.into_payment_address() {
                Some(v) => v,
                None => return Err("Invalid address_sender"),
            };

            // Get address_recipient with the type
            let saddr_recipient = match  address_recipient.into_payment_address() {
                Some(v) => v,
                None => return Err("Invalid address_recipient"),
            };

            // Get value_sender with the type
            let svalue_sender = match value_sender.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid value_sender"),
            };

            // Get value_recipient with the type
            let svalue_recipient = match value_recipient.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid value_recipient"),
            };

            // Get balance_sender with the type
            let sbalance_sender = match balance_sender.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid balance_sender"),
            };

            // Get rk with the type
            let srk = match rk.into_verification_key() {
                Some(v) => v,
                None => return Err("Invalid rk"),
            };                      

            // Verify the zk proof
            ensure!(
                Self::validate_proof(
                    &szkproof,
                    &saddr_sender,
                    &saddr_recipient,
                    &svalue_sender,
                    &svalue_recipient,
                    &sbalance_sender,
                    &srk,                    
                ),
                "Invalid zkproof"
            );  

            // Verify the balance
            ensure!(
                Self::encrypted_balance(address_sender).unwrap() == balance_sender.clone(),
                "Invalid encrypted balance"
            );

            // Get balance_sender with the type
            let bal_sender = match Self::encrypted_balance(address_sender) {
                Some(b) => match b.into_ciphertext() {
                    Some(c) => c,
                    None => return Err("Invalid ciphertext of sender balance"),
                },
                None => return Err("Invalid sender balance"),
            };

            // Get balance_recipient with the option type
            let bal_recipient = match Self::encrypted_balance(address_recipient) {
                Some(b) => b.into_ciphertext(),
                _ => None
            };            
            
            // Update the sender's balance
            <EncryptedBalance<T>>::mutate(address_sender, |balance| {
                let new_balance = balance.clone().map(
                    |_| Ciphertext::from_ciphertext(&bal_sender.sub_no_params(&svalue_sender)));
                *balance = new_balance
            });

            // Update the recipient's balance
            <EncryptedBalance<T>>::mutate(address_recipient, |balance| {
                let new_balance = balance.clone().map_or(
                    Some(Ciphertext::from_ciphertext(&svalue_recipient)),                    
                    |_| Some(Ciphertext::from_ciphertext(&bal_recipient.unwrap().add_no_params(&svalue_recipient)))
                );
                *balance = new_balance
            });

            // TODO: tempolaly removed address_sender and address_recipient because of mismatched types
            Self::deposit_event(RawEvent::ConfTransfer(zkproof, value_sender, value_recipient, balance_sender, rk));

            Ok(())         			            
		}		
	}
}

decl_storage! {
    trait Store for Module<T: Trait> as ConfTransfer {
        // The encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map PkdAddress => Option<Ciphertext>; 
        // The verification key of zk proofs (only readable)
        pub VerifyingKey get(verifying_key) config(): PreparedVk;                 
    }
}

decl_event! (
    /// An event in this module.
	pub enum Event<T> where <T as system::Trait>::AccountId {    
        // TODO: tempolaly removed AccountId because of mismatched types
		ConfTransfer(Proof, Ciphertext, Ciphertext, Ciphertext, SigVerificationKey),
        Phantom(AccountId),
	}
);

impl<T: Trait> Module<T> {
    // Public immutables
    // Validate zk proofs
	pub fn validate_proof (    
        zkproof: &bellman_verifier::Proof<Bls12>,
        address_sender: &PaymentAddress<Bls12>,
        address_recipient: &PaymentAddress<Bls12>,
        value_sender: &elgamal::Ciphertext<Bls12>,
        value_recipient: &elgamal::Ciphertext<Bls12>,
        balance_sender: &elgamal::Ciphertext<Bls12>,
        rk: &PublicKey<Bls12>,                 
    ) -> bool {
        // Construct public input for circuit
        let mut public_input = [Fr::zero(); 12];

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
        // {
        //     let (x, y) = balance_sender.left.into_xy();
        //     public_input[10] = x;
        //     public_input[11] = y;
        // }
        // {
        //     let (x, y) = balance_sender.right.into_xy();
        //     public_input[12] = x;
        //     public_input[13] = y;
        // }
        {
            let (x, y) = rk.0.into_xy();
            public_input[10] = x;
            public_input[11] = y;
        }

        let pvk = Self::verifying_key().into_prepared_vk().unwrap();        

        // Verify the proof
        match verify_proof(&pvk, &zkproof, &public_input[..]) {
            // No error, and proof verification successful
            Ok(true) => true,
            _ => {runtime_io::print("Invalid proof!!!!!!!!!!!!!!"); false},                
        }        
    } 

    // fn is_small_order<Order>(p: &edwards::Point<Bls12, Order>, params: &JubjubBls12) -> bool {
    //     p.double(params).double(params).double(params) == edwards::Point::zero()
    // }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use runtime_io::with_externalities;
    use support::{impl_outer_origin, assert_ok};
    use primitives::{H256, Blake2Hasher};
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256, IdentityLookup},
        testing::{Digest, DigestItem, Header}
    };
    use keys::{ExpandedSpendingKey, ViewingKey};    
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};        
    use hex_literal::{hex, hex_impl};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};    

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;

    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Digest = Digest;
        type AccountId = u64;
        type Lookup = IdentityLookup<u64>;
        type Header = Header;
        type Event = ();
        type Log = DigestItem;
    }

    impl Trait for Test {
        type Event = ();
    }

    type ConfTransfer = Module<Test>;
    

    fn alice_init() -> (PkdAddress, Ciphertext) {
        let alice_seed = b"Alice                           ";	
        let alice_value = 100 as u32;

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

        let expsk = ExpandedSpendingKey::<Bls12>::from_spending_key(alice_seed);        
        let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&expsk, params);    
        
        let address = viewing_key.into_payment_address(params);	

        // The default balance is not encrypted with randomness.
        let enc_alice_bal = elgamal::Ciphertext::encrypt(alice_value, fs::Fs::one(), &address.0, p_g, params);

        let ivk = viewing_key.ivk();	

        let dec_alice_bal = enc_alice_bal.decrypt(ivk, p_g, params).unwrap();
        assert_eq!(dec_alice_bal, alice_value);	

        (PkdAddress::from_payment_address(&address), Ciphertext::from_ciphertext(&enc_alice_bal))
    }

    fn get_pvk() -> PreparedVk {
        let vk_path = Path::new("../demo/cli/verification.params"); 
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();
        
        PreparedVk(buf_vk)
    }

    fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
        let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
        t.extend(GenesisConfig::<Test>{
            encrypted_balance: vec![alice_init()],
            verifying_key: get_pvk(),
            _genesis_phantom_data: Default::default(),
        }.build_storage().unwrap().0);
        t.into()
    }

    #[test]    
    fn test_call_function() {        
        with_externalities(&mut new_test_ext(), || {                 
            let proof: [u8; 192] = hex!("a97fd1cb914a07033e277f5562351eda7648a29edc3b65f28fe8221f21cb3e94c64f726f6944173662fa98c2980eafc095b9dd7542ed13cb30ce4bbdddf974a8028e9c91ea3a5ab88d5fa684ad49652fd651147c7cf42975f7435e71e238c88611a14b1cda6b7cde218f1b90d272262ac042f8426e748b1cd7efe7917a4cc9b6a7bae60fb089c59af7ce0e23cb9745d592530edeab7ec1869dea11f31c842e168898eb2ce9f77be4597ba2b8367ccfd70d375ebd3c5547c58244163e3e16ef03");
            let pkd_addr_alice: [u8; 32] = hex!("775e501abc59d035e71e16c6c6cd225d44a249289dd95c37516ce4754721d763");
            let pkd_addr_bob: [u8; 32] = hex!("a23bb484f72b28a4179a71057c4528648dfb37974ccd84b38aa3e342f9598515");
            let enc10_by_alice: [u8; 64] = hex!("d6544e8aebd4f9a41c80fd6669077805a402418fcf2fa18e01e86b6d2ab1313a592c414431f34c45d4b494cc2eb43a0b50de7b717a0a092f3db2aa71ad4c5286");
            let enc10_by_bob: [u8; 64] = hex!("3d74a2b5e9ee19e7e88a0e8b12e39ca68f818911cb4bc5decda6b29143c986a3592c414431f34c45d4b494cc2eb43a0b50de7b717a0a092f3db2aa71ad4c5286");            
            let enc100_by_alice: [u8; 64] = hex!("3f101bd6575876bbf772e25ed84728e012295b51f1be37b8451553184b458aeeac776c796563fcd44cc49cfaea8bb796952c266e47779d94574c10ad01754b11");            
            let rvk: [u8; 32] = hex!("791b91fae07feada7b6f6042b1e214bc75759b3921956053936c38a95271a834");

            assert_ok!(ConfTransfer::confidential_transfer(
                Origin::signed(1),
                Proof(proof.to_vec()),
                PkdAddress::from_slice(&pkd_addr_alice),
                PkdAddress::from_slice(&pkd_addr_bob),
                Ciphertext(enc10_by_alice.to_vec()),
                Ciphertext(enc10_by_bob.to_vec()),
                Ciphertext(enc100_by_alice.to_vec()),                
                SigVerificationKey::from_slice(&rvk)
            ));
        })
    }        
}
