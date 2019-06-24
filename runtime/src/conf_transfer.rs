//! A simple module for dealing with confidential transfer of fungible assets.
use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure};
use rstd::prelude::*;
use bellman_verifier::verify_proof;
use rstd::result;
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

        /// The pending transfer
        pub PendingTransfer get(pending_transfer) config() : map PkdAddress => Option<Ciphertext>;

        /// The last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map PkdAddress => Option<T::BlockNumber>;

        /// Global epoch length for rollover.
        /// The longer epoch length is, the longer rollover time is.
        /// This parameter should be fixed based on trade-off between UX and security in terms of front-running attacks.
        pub EpochLength get(epoch_length) config() : T::BlockNumber;

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
    // PUBLIC IMMUTABLES

    /// Validate zk proofs
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

    // PRIVATE MUTABLES

    /// Rolling over allows us to send transactions asynchronously and protect from front-running attacks.
    /// We rollover an account in an epoch when the first message from this account is received;
    /// so, one message rolls over only one account.
    /// To achieve this, we define a separate (internal) method for rolling over,
    /// and the first thing every other method does is to call this method.
    /// More details in Section 3.1: https://crypto.stanford.edu/~buenz/papers/zether.pdf
    fn rollover(addr: &PkdAddress) -> result::Result<elgamal::Ciphertext<Bls12>, &'static str> {
        let current_height = <system::Module<T>>::block_number();
        let current_epoch = current_height / Self::epoch_length();

        // Get current pending transfer
        let pending_transfer = <PendingTransfer<T>>::get(addr);

        // Get balance with the type
        let typed_balance = match Self::encrypted_balance(addr) {
            Some(b) => match b.into_ciphertext() {
                Some(c) => c,
                None => return Err("Invalid ciphertext"),
            },
            None => return Err("Invalid balance"),
        };

        // Get balance with the type
        let typed_pending_transfer = match pending_transfer.clone() {
            Some(b) => match b.into_ciphertext() {
                Some(c) => c,
                None => return Err("Invalid ciphertext"),
            },
            None => return Err("Invalid balance"),
        };

        if let Some(e) = <LastRollOver<T>>::get(addr) {
            // checks if the last roll over was in an older epoch
            if e < current_epoch {
                // transfer balance from pending_transfer to actual balance
                <EncryptedBalance<T>>::mutate(addr, |balance| {
                    let new_balance = balance.clone().map_or(
                        pending_transfer,
                        |_| Some(Ciphertext::from_ciphertext(&typed_balance.add_no_params(&typed_pending_transfer)))
                    );
                    *balance = new_balance
                });

                // Reset pending_transfer.
                <PendingTransfer<T>>::remove(addr);

                // Set last rollover to current epoch.
                <LastRollOver<T>>::insert(addr, current_epoch);
            }
        }

        Ok(typed_balance)
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

    fn alice_balance_init() -> (PkdAddress, Ciphertext) {
        let (alice_seed, enc_key) = get_alice_seed_ek();
        let alice_amount = 100 as u32;
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

        // The default balance is not encrypted with randomness.
        let enc_alice_bal = elgamal::Ciphertext::encrypt(
            alice_amount,
            fs::Fs::one(),
            &enc_key,
            p_g,
            params
        );

        let decryption_key = ProofGenerationKey::<Bls12>::from_seed(&alice_seed[..], params).into_decryption_key().unwrap();

        let dec_alice_bal = enc_alice_bal.decrypt(&decryption_key, p_g, params).unwrap();
        assert_eq!(dec_alice_bal, alice_amount);

        (PkdAddress::from_encryption_key(&enc_key), Ciphertext::from_ciphertext(&enc_alice_bal))
    }

    fn alice_pending_transfer_init() -> (PkdAddress, Ciphertext) {
        let (_, enc_key) = get_alice_seed_ek();
        let zero = elgamal::Ciphertext::zero();

        (PkdAddress::from_encryption_key(&enc_key), Ciphertext::from_ciphertext(&zero))
    }

    fn alice_epoch_init() -> (PkdAddress, u64) {
        let (_, enc_key) = get_alice_seed_ek();

        (PkdAddress::from_encryption_key(&enc_key), 0)
    }

    fn get_alice_seed_ek() -> (Vec<u8>, EncryptionKey<Bls12>) {
        let params = &JubjubBls12::new();
        let alice_seed = b"Alice                           ".to_vec();

        (alice_seed.clone(), EncryptionKey::<Bls12>::from_seed(&alice_seed[..], params)
            .expect("should be generated encryption key from seed."))
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
            encrypted_balance: vec![alice_balance_init()],
			pending_transfer: vec![alice_pending_transfer_init()],
			last_epoch: vec![alice_epoch_init()],
            epoch_length: 10,
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
            let proof: [u8; 192] = hex!("a127994f62fefa882271cbe9fd1fffd16bcf3ebb3cd219c04be4333118f33115e4c70e8d199e43e956b8761e1e69bff48ff156d14e7d083a09e341da114b05a5c2eff9bd6aa9881c7ca282fbb554245d2e65360fa72f1de6b538b79a672cdf86072eeb911b1dadbfef2091629cf9ee76cf80ff7ec085258b102caa62f5a2a00b48dce27c91d59c2cdfa23b456c0f616ea1e9061b5e91ec080f1c3c66cf2e13ecca7b7e1530addd2977a123d6ebbea11e9f8c3b1989fc830a309254e663315dcb");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("29f38e21e264fb8fa61edc76f79ca2889228d36e40b63f3697102010404ae1d0b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");
            let enc10_by_bob: [u8; 64] = hex!("4c6bda3db6977c29a115fbc5aba03b9c37b767c09ffe6c622fcec42bbb732fc7b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let enc1_by_alice: [u8; 64] = hex!("ed19f1820c3f09da976f727e8531aa83a483d262e4abb1e9e67a1eba843b4034b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");

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
            let proof: [u8; 192] = hex!("b127994f62fefa882271cbe9fd1fffd16bcf3ebb3cd219c04be4333118f33115e4c70e8d199e43e956b8761e1e69bff48ff156d14e7d083a09e341da114b05a5c2eff9bd6aa9881c7ca282fbb554245d2e65360fa72f1de6b538b79a672cdf86072eeb911b1dadbfef2091629cf9ee76cf80ff7ec085258b102caa62f5a2a00b48dce27c91d59c2cdfa23b456c0f616ea1e9061b5e91ec080f1c3c66cf2e13ecca7b7e1530addd2977a123d6ebbea11e9f8c3b1989fc830a309254e663315dcb");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("29f38e21e264fb8fa61edc76f79ca2889228d36e40b63f3697102010404ae1d0b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");
            let enc10_by_bob: [u8; 64] = hex!("4c6bda3db6977c29a115fbc5aba03b9c37b767c09ffe6c622fcec42bbb732fc7b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let enc1_by_alice: [u8; 64] = hex!("ed19f1820c3f09da976f727e8531aa83a483d262e4abb1e9e67a1eba843b4034b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");

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
