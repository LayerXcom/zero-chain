//! A simple module for dealing with confidential transfer of fungible assets.
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
use keys::EncryptionKey;
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
            rk: SigVerificationKey  // TODO: Extract from origin            
        ) -> Result {            
			// let rk = ensure_signed(origin)?;            
            
            // Get zkproofs with the type
            let szkproof = match zkproof.into_proof() {
                Some(v) => v,
                None => return Err("Invalid zkproof"),
            };

            // Get address_sender with the type
            let saddr_sender = match address_sender.into_encryption_key() {
                Some(v) => v,
                None => return Err("Invalid address_sender"),
            };

            // Get address_recipient with the type
            let saddr_recipient = match  address_recipient.into_encryption_key() {
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

            // Get rk with the type
            let srk = match rk.into_verification_key() {
                Some(v) => v,
                None => return Err("Invalid rk"),
            };                 

            // Get balance_sender with the type
            let bal_sender = match Self::encrypted_balance(address_sender) {
                Some(b) => match b.into_ciphertext() {
                    Some(c) => c,
                    None => return Err("Invalid ciphertext of sender balance"),
                },
                None => return Err("Invalid sender balance"),
            };     

            // Verify the zk proof
            ensure!(
                Self::validate_proof(
                    &szkproof,
                    &saddr_sender,
                    &saddr_recipient,
                    &svalue_sender,
                    &svalue_recipient,
                    &bal_sender,
                    &srk,                    
                ),
                "Invalid zkproof"
            );                        

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
            Self::deposit_event(RawEvent::ConfTransfer(zkproof, value_sender, value_recipient, Ciphertext::from_ciphertext(&bal_sender), rk));

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
        address_sender: &EncryptionKey<Bls12>,
        address_recipient: &EncryptionKey<Bls12>,
        value_sender: &elgamal::Ciphertext<Bls12>,
        value_recipient: &elgamal::Ciphertext<Bls12>,
        balance_sender: &elgamal::Ciphertext<Bls12>,
        rk: &PublicKey<Bls12>,                 
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
            _ => {runtime_io::print("Invalid proof!!!!"); false},                
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
    use keys::{ProofGenerationKey, EncryptionKey};    
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

        let ek = EncryptionKey::<Bls12>::from_ok_bytes(alice_seed, params);                

        // The default balance is not encrypted with randomness.
        let enc_alice_bal = elgamal::Ciphertext::encrypt(alice_value, fs::Fs::one(), &ek.0, p_g, params);

        let bdk = ProofGenerationKey::<Bls12>::from_ok_bytes(alice_seed, params).bdk();        

        let dec_alice_bal = enc_alice_bal.decrypt(bdk, p_g, params).unwrap();
        assert_eq!(dec_alice_bal, alice_value);	            

        (PkdAddress::from_encryption_key(&ek), Ciphertext::from_ciphertext(&enc_alice_bal))
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
            let proof: [u8; 192] = hex!("923bd0c3ea54b147372c78ca6f540f8deee4c91674aa592a5a075ab8868d7d18fc51e7aa8b4c3eb39ebdae25e44289ce8711e926a6828f89c398e4e6d97b2aa0115111a60a8bbbfb9bdc4a1ba27c1dde77ed88a0350c7e2e17ce1d8c4fd5004d152f57afd5ccb911f3c27c04aff88e779c8c1a116f18d84945eab501d4fca3575e64b06966c19b7a8fcf350bf8cee9199085d91754bdf944cf237364d0c57a21e9778b33de7490772372bbe7503eb725cb016fb0c98ce54fff4e33625a24d3c1");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("ecb7fc55e2e2a1a37a1ede19008dfc885b30bf2d0764f4676818ce932a87e4351d6edd052ce792abb1f6df14a6b58f9571a9a97d1d765557d70567b9cffe9ee0");
            let enc10_by_bob: [u8; 64] = hex!("6956c7e9b9a7a6d638065635e1cd968884957b9e9348ad7670dbc205eca01cb71d6edd052ce792abb1f6df14a6b58f9571a9a97d1d765557d70567b9cffe9ee0");                        
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");

            assert_ok!(ConfTransfer::confidential_transfer(
                Origin::signed(1),
                Proof(proof.to_vec()),
                PkdAddress::from_slice(&pkd_addr_alice),
                PkdAddress::from_slice(&pkd_addr_bob),
                Ciphertext(enc10_by_alice.to_vec()),
                Ciphertext(enc10_by_bob.to_vec()),                       
                SigVerificationKey::from_slice(&rvk)
            ));
        })
    }        
}
