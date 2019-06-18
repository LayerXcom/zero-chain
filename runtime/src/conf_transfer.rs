//! A simple module for dealing with confidential transfer of fungible assets.
use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure};
use rstd::prelude::*;
use bellman_verifier::verify_proof;
use pairing::{
    bls12_381::{
        Bls12,
        Fr,
    },
    Field,
};
use jubjub::redjubjub::PublicKey;
use zprimitives::{
    PkdAddress,
    Ciphertext,
    Proof,
    SigVerificationKey,
    PreparedVk,
};
use keys::EncryptionKey;
use zcrypto::elgamal;
use runtime_io;


pub trait Trait: system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

type FeeAmount = u32;

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
            amount_sender: Ciphertext,
            amount_recipient: Ciphertext,
            rvk: SigVerificationKey,  // TODO: Extract from origin
            fee_sender: Ciphertext
        ) -> Result {
			// let rvk = ensure_signed(origin)?;

            // Get zkproofs with the type
            let typed_zkproof = match zkproof.into_proof() {
                Some(v) => v,
                None => return Err("Invalid zkproof"),
            };

            // Get address_sender with the type
            let typed_addr_sender = match address_sender.into_encryption_key() {
                Some(v) => v,
                None => return Err("Invalid address_sender"),
            };

            // Get address_recipient with the type
            let typed_addr_recipient = match  address_recipient.into_encryption_key() {
                Some(v) => v,
                None => return Err("Invalid address_recipient"),
            };

            // Get amount_sender with the type
            let typed_amount_sender = match amount_sender.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid amount_sender"),
            };

            // Get amount_recipient with the type
            let typed_amount_recipient = match amount_recipient.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid amount_recipient"),
            };

            // Get fee_sender with the type
            let typed_fee_sender = match fee_sender.into_ciphertext() {
                Some(v) => v,
                None => return Err("Invalid fee_sender"),
            };

            // Get rvk with the type
            let typed_rvk = match rvk.into_verification_key() {
                Some(v) => v,
                None => return Err("Invalid rvk"),
            };

            // Get balance_sender with the type
            let typed_bal_sender = match Self::encrypted_balance(address_sender) {
                Some(b) => match b.into_ciphertext() {
                    Some(c) => c,
                    None => return Err("Invalid ciphertext of sender balance"),
                },
                None => return Err("Invalid sender balance"),
            };

            // Verify the zk proof
            ensure!(
                Self::validate_proof(
                    &typed_zkproof,
                    &typed_addr_sender,
                    &typed_addr_recipient,
                    &typed_amount_sender,
                    &typed_amount_recipient,
                    &typed_bal_sender,
                    &typed_rvk,
                    &typed_fee_sender,
                ),
                "Invalid zkproof"
            );

            // Get balance_recipient with the option type
            let typed_bal_recipient = match Self::encrypted_balance(address_recipient) {
                Some(b) => b.into_ciphertext(),
                _ => None
            };

            let amount_plus_fee = typed_amount_sender.add_no_params(&typed_fee_sender);

            // Update the sender's balance
            <EncryptedBalance<T>>::mutate(address_sender, |balance| {
                let new_balance = balance.clone().map(
                    |_| Ciphertext::from_ciphertext(&typed_bal_sender.sub_no_params(&amount_plus_fee)));
                *balance = new_balance
            });

            // Update the recipient's balance
            <EncryptedBalance<T>>::mutate(address_recipient, |balance| {
                let new_balance = balance.clone().map_or(
                    Some(Ciphertext::from_ciphertext(&typed_amount_recipient)),
                    |_| Some(Ciphertext::from_ciphertext(&typed_bal_recipient.unwrap().add_no_params(&typed_amount_recipient)))
                );
                *balance = new_balance
            });

            // TODO: tempolaly removed address_sender and address_recipient because of mismatched types
            Self::deposit_event(
                RawEvent::ConfTransfer(
                    zkproof,
                    amount_sender,
                    amount_recipient,
                    Ciphertext::from_ciphertext(&typed_bal_sender),
                    rvk
                )
            );

            Ok(())
		}
	}
}

decl_storage! {
    trait Store for Module<T: Trait> as ConfTransfer {
        /// The encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map PkdAddress => Option<Ciphertext>;
        /// The fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config(): FeeAmount;
        /// The verification key of zk proofs (only readable)
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
        amount_sender: &elgamal::Ciphertext<Bls12>,
        amount_recipient: &elgamal::Ciphertext<Bls12>,
        balance_sender: &elgamal::Ciphertext<Bls12>,
        rvk: &PublicKey<Bls12>,
        fee_sender: &elgamal::Ciphertext<Bls12>
    ) -> bool {
        // Construct public input for circuit
        let mut public_input = [Fr::zero(); 18];

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
            let (x, y) = amount_sender.left.into_xy();
            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = amount_recipient.left.into_xy();
            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = amount_sender.right.into_xy();
            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = fee_sender.left.into_xy();
            public_input[10] = x;
            public_input[11] = y;
        }
        {
            let (x, y) = balance_sender.left.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = balance_sender.right.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }
        {
            let (x, y) = rvk.0.into_xy();
            public_input[16] = x;
            public_input[17] = y;
        }

        let pvk = Self::verifying_key().into_prepared_vk().unwrap();

        // Verify the provided proof
        match verify_proof(&pvk, &zkproof, &public_input[..]) {
            // No error, and proof verification successful
            Ok(is_true) => is_true,
            Err(_) => {runtime_io::print("Invalid proof!!"); false},
        }
    }
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
        type SigVerificationKey = u64;
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
        let alice_amount = 100 as u32;

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

        let encryption_key = EncryptionKey::<Bls12>::from_seed(alice_seed, params).unwrap();

        // The default balance is not encrypted with randomness.
        let enc_alice_bal = elgamal::Ciphertext::encrypt(
            alice_amount,
            fs::Fs::one(),
            &encryption_key,
            p_g,
            params
        );

        let decryption_key = ProofGenerationKey::<Bls12>::from_seed(alice_seed, params).into_decryption_key().unwrap();

        let dec_alice_bal = enc_alice_bal.decrypt(&decryption_key, p_g, params).unwrap();
        assert_eq!(dec_alice_bal, alice_amount);

        (PkdAddress::from_encryption_key(&encryption_key), Ciphertext::from_ciphertext(&enc_alice_bal))
    }

    fn get_pvk() -> PreparedVk {
        let vk_path = Path::new("../zeroc/verification.params");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVk::from_slice(&buf_vk[..])
    }

    fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
        let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
        t.extend(GenesisConfig::<Test>{
            encrypted_balance: vec![alice_init()],
            verifying_key: get_pvk(),
            transaction_base_fee: 1,
            _genesis_phantom_data: Default::default(),
        }.build_storage().unwrap().0);

        t.into()
    }

    #[test]
    fn test_call_function() {
        with_externalities(&mut new_test_ext(), || {
            // Needed to be updated manually once snark paramters are pre-processed.
            let proof: [u8; 192] = hex!("80820f58804a32f4ecc8a7469275cac8bc0a728fca43fea67317519745e607aeb5b4bd4366b62fb6c5e9cd3a83bd232a99932412198c014b509d2e88bf5f01075202eab7c02adbf8a7f10be3e46c7a8c48e0393d16d1379f6671978892d363350b2bf0665b201523b294dc20f2427b531c17f3f6a513cad8e31184a31effca26bae94f7e43c0e01e18b2cf55bfa66c21a6c065a94df6c9199db5f4e1a3414037b2a3538bf99ca2e797f24158dec752017facff03bd11f2ebe3c33308e4b40115");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("e9ef0a4f4b07f7ae5bfab360e3daa312c2d288e21eb4b9ccc9946c7926efa50ea846bca1ff93a24c5bb8efbde8a42424ef343244b729eaa367df7bb7ac0c3fcf");
            let enc10_by_bob: [u8; 64] = hex!("018ba6d82d18eaa6751306dcf188daa771bb0ce270cadb91a8b13846b85cc457a846bca1ff93a24c5bb8efbde8a42424ef343244b729eaa367df7bb7ac0c3fcf");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let enc1_by_alice: [u8; 64] = hex!("dc98926ce4d481770442acd13814a923cc2024d31463fcc7ce0dd9aed6ae64afa846bca1ff93a24c5bb8efbde8a42424ef343244b729eaa367df7bb7ac0c3fcf");

            assert_ok!(ConfTransfer::confidential_transfer(
                Origin::signed(1),
                Proof::from_slice(&proof[..]),
                PkdAddress::from_slice(&pkd_addr_alice),
                PkdAddress::from_slice(&pkd_addr_bob),
                Ciphertext::from_slice(&enc10_by_alice[..]),
                Ciphertext::from_slice(&enc10_by_bob[..]),
                SigVerificationKey::from_slice(&rvk),
                Ciphertext::from_slice(&enc1_by_alice[..])
            ));
        })
    }

    #[test]
    #[should_panic]
    fn test_call_with_worng_proof() {
        with_externalities(&mut new_test_ext(), || {
            let proof: [u8; 192] = hex!("b7e763cbdc1d4b78e70534894d9dbef78ac259ab0cd602e65d31459dd03432c5e14dbef9484a9ab36d9db17ad531b50aa8d051dc885599fbefcd1992437ee3453ef66d5921b9082c5ac93ddf7370dac444050147a71849cc1d16d4208984335d1567bb676a30974e8ae228741adbf6ac50d3c35ee14e835762bc4868e6f22d7b69ccbbbc5cfc3fbe49968c1873a99ffcacb71b1139806166e5c491ff9addbcbabc9df058371ef989219ba20c6a718317b4586bbf1d429d4bf4dab47e130bd23f");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("087d5aa97ed351a81cea9e7bb46c83bb4a889bc696f623e7812fc59509cc3a6c997173e746fe32c12a70584cdf9dce783cf3daf44c17d40142f2c460324355aa");
            let enc10_by_bob: [u8; 64] = hex!("88c851325af572216ececdc2e120bfa972ed9e6b901ee45e31288abd84c3b6be997173e746fe32c12a70584cdf9dce783cf3daf44c17d40142f2c460324355aa");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let enc1_by_alice: [u8; 64] = hex!("55a75030bd77f5b7914b55575c154f61a721e05df076546d815e877d71ac6dcc997173e746fe32c12a70584cdf9dce783cf3daf44c17d40142f2c460324355aa");

            assert_ok!(ConfTransfer::confidential_transfer(
                Origin::signed(1),
                Proof::from_slice(&proof[..]),
                PkdAddress::from_slice(&pkd_addr_alice),
                PkdAddress::from_slice(&pkd_addr_bob),
                Ciphertext::from_slice(&enc10_by_alice[..]),
                Ciphertext::from_slice(&enc10_by_bob[..]),
                SigVerificationKey::from_slice(&rvk),
                Ciphertext::from_slice(&enc1_by_alice[..])
            ));
        })
    }


}
