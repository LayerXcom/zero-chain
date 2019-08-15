//! A module for dealing with confidential transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::TryInto;
use pairing::bls12_381::Bls12;
use runtime_primitives::traits::Zero;
use jubjub::redjubjub::PublicKey;
use zprimitives::{
    EncKey, Proof, ElgamalCiphertext, SigVk, Nonce, RightCiphertext, LeftCiphertext, Ciphertext,
};
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait + zk_system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

pub struct TypedParams {
    pub zkproof: bellman_verifier::Proof<Bls12>,
    pub address_sender: EncryptionKey<Bls12>,
    pub address_recipient: EncryptionKey<Bls12>,
    pub enc_amount_sender: elgamal::Ciphertext<Bls12>,
    pub enc_amount_recipient: elgamal::Ciphertext<Bls12>,
    pub enc_fee: elgamal::Ciphertext<Bls12>,
    pub rvk: PublicKey<Bls12>,
}

type FeeAmount = u32;

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initializing events
		// this is needed only if you are using events in your module
		fn deposit_event<T>() = default;

		pub fn confidential_transfer(
            origin,
            zkproof: Proof,
            address_sender: EncKey,
            address_recipient: EncKey,
            amount_sender: LeftCiphertext,
            amount_recipient: LeftCiphertext,
            fee_sender: LeftCiphertext,
            randomness: RightCiphertext,
            nonce: Nonce
        ) -> Result {
			let rvk = ensure_signed(origin)?;

            // Convert provided parametrs into typed ones.
            let typed = Self::into_types(
                &zkproof,
                &address_sender,
                &address_recipient,
                &amount_sender,
                &amount_recipient,
                &fee_sender,
                &rvk,
                &randomness
            )
            .map_err(|_| "Failed to convert into types.")?;

            // Rollover and get sender's balance.
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            let typed_balance_sender = Self::rollover(&address_sender)
                .map_err(|_| "Invalid ciphertext of sender balance.")?;

            // Rollover and get recipient's balance
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            let typed_balance_recipient = Self::rollover(&address_recipient)
                .map_err(|_| "Invalid ciphertext of recipient balance.")?;

            // Veridate the provided nonce isn't included in the nonce pool.
            assert!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce));

            // Verify the zk proof
            if !<zk_system::Module<T>>::validate_confidential_proof(
                    &typed.zkproof,
                    &typed.address_sender,
                    &typed.address_recipient,
                    &typed.enc_amount_sender,
                    &typed.enc_amount_recipient,
                    &typed_balance_sender,
                    &typed.rvk,
                    &typed.enc_fee,
                    &nonce.try_into().map_err(|_| "Failed to convert from Nonce.")?
                )? {
                    Self::deposit_event(RawEvent::InvalidZkProof());
                    return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            // Subtracting transferred amount and fee from the sender's encrypted balances.
            // This function causes a storage mutation.
            Self::sub_enc_balance(&address_sender, &typed_balance_sender, &typed.enc_amount_sender, &typed.enc_fee);

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(&address_recipient, &typed_balance_recipient, &typed.enc_amount_recipient);

            Self::deposit_event(
                RawEvent::ConfidentialTransfer(
                    zkproof,
                    address_sender,
                    address_recipient,
                    amount_sender,
                    amount_recipient,
                    fee_sender,
                    randomness,
                    Ciphertext::from_ciphertext(&typed_balance_sender),
                    rvk
                )
            );

            Ok(())
		}
	}
}

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedBalances {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map EncKey => Option<Ciphertext>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map EncKey => Option<Ciphertext>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map EncKey => Option<T::BlockNumber>;

        /// A fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config(): FeeAmount;
    }
}

decl_event! (
    /// An event in this module.
	pub enum Event<T> where <T as system::Trait>::AccountId {
		ConfidentialTransfer(Proof, EncKey, EncKey, LeftCiphertext, LeftCiphertext, LeftCiphertext, RightCiphertext, Ciphertext, AccountId),
        InvalidZkProof(),
	}
);

impl<T: Trait> Module<T> {
    // PUBLIC IMMUTABLES

    /// Convert provided parametrs into typed ones.
    pub fn into_types(
        zkproof: &Proof,
        address_sender: &EncKey,
        address_recipient: &EncKey,
        amount_sender: &LeftCiphertext,
        amount_recipient: &LeftCiphertext,
        fee_sender: &LeftCiphertext,
        rvk: &T::AccountId,
        randomness: &RightCiphertext
    ) -> result::Result<TypedParams, &'static str>
    {
        // Get zkproofs with the type
        let typed_zkproof = zkproof
            .into_proof()
            .ok_or("Invalid zkproof")?;

        // Get address_sender with the type
        let typed_addr_sender = address_sender
            .into_encryption_key()
            .ok_or("Invalid address_sender")?;

        // Get address_recipient with the type
        let typed_addr_recipient = address_recipient
            .into_encryption_key()
            .ok_or("Invalid address_recipient")?;

        // Get encrypted amount_sender with the type
        let enc_amount_sender = elgamal::Ciphertext::new(
            amount_sender.try_into().map_err(|_| "Failed to read amount_sender.")?,
            randomness.try_into().map_err(|_| "Failed to read randomness.")?,
            );

        // Get encrypted amount_recipient with the type
        let enc_amount_recipient = elgamal::Ciphertext::new(
            amount_recipient.try_into().map_err(|_| "Failed to read amount_recipient.")?,
            randomness.try_into().map_err(|_| "Failed to read randomness.")?,
            );

        // Get encrypted fee with the type
        let enc_fee = elgamal::Ciphertext::new(
            amount_recipient.try_into().map_err(|_| "Failed to read enc_fee.")?,
            randomness.try_into().map_err(|_| "Failed to read randomness.")?,
            );

        // Get rvk with the type
        let typed_rvk = rvk
            .into_verification_key()
            .ok_or("Invalid rvk")?;

        Ok(TypedParams {
            zkproof: typed_zkproof,
            address_sender: typed_addr_sender,
            address_recipient: typed_addr_recipient,
            enc_amount_sender,
            enc_amount_recipient,
            enc_fee,
            rvk:typed_rvk,
        })
    }

    // PUBLIC MUTABLES

    /// Rolling over allows us to send transactions asynchronously and protect from front-running attacks.
    /// We rollover an account in an epoch when the first message from this account is received;
    /// so, one message rolls over only one account.
    /// To achieve this, we define a separate (internal) method for rolling over,
    /// and the first thing every other method does is to call this method.
    /// More details in Section 3.1: https://crypto.stanford.edu/~buenz/papers/zether.pdf
    pub fn rollover(addr: &EncKey) -> result::Result<elgamal::Ciphertext<Bls12>, &'static str> {
        let current_epoch = <zk_system::Module<T>>::get_current_epoch();

        let last_rollover = match Self::last_rollover(addr) {
            Some(l) => l,
            None => T::BlockNumber::zero(),
        };

        // Get current pending transfer
        let pending_transfer = Self::pending_transfer(addr);

        let zero = elgamal::Ciphertext::zero();

        // Get balance with the type
        let typed_balance = match Self::encrypted_balance(addr) {
            Some(b) => b.into_ciphertext().ok_or("Invalid balance ciphertext")?,
            None => zero.clone(),
        };

        // Get balance with the type
        let typed_pending_transfer = match pending_transfer.clone() {
            Some(b) => b.into_ciphertext().ok_or("Invalid pending_transfer ciphertext")?,
            // If pending_transfer is `None`, just return zero value ciphertext.
            None => zero.clone(),
        };

        // Checks if the last roll over was in an older epoch.
        // If so, some storage changes are happend here.
        if last_rollover < current_epoch {
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

        let res_balance = match Self::encrypted_balance(addr) {
            Some(b) => b.into_ciphertext().ok_or("Invalid balance ciphertext")?,
            None => zero.clone(),
        };

        // Initialize a nonce pool
        <zk_system::Module<T>>::init_nonce_pool(current_epoch);

        // return actual typed balance.
        Ok(res_balance)
    }

    // Subtracting transferred amount and fee from encrypted balances.
    pub fn sub_enc_balance(
        address: &EncKey,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>,
        typed_fee: &elgamal::Ciphertext<Bls12>
    ) {
        let amount_plus_fee = typed_amount.add_no_params(&typed_fee);

        <EncryptedBalance<T>>::mutate(address, |balance| {
            let new_balance = balance.clone().map(
                |_| Ciphertext::from_ciphertext(&typed_balance.sub_no_params(&amount_plus_fee)));
            *balance = new_balance
        });
    }

    /// Adding transferred amount to pending transfer.
    pub fn add_pending_transfer(
        address: &EncKey,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>
    ) {
        <PendingTransfer<T>>::mutate(address, |pending_transfer| {
            let new_pending_transfer = pending_transfer.clone().map_or(
                Some(Ciphertext::from_ciphertext(&typed_amount)),
                |_| Some(Ciphertext::from_ciphertext(&typed_balance.add_no_params(&typed_amount)))
            );
            *pending_transfer = new_pending_transfer
        });
    }
}

impl<T: Trait> IsDeadAccount<T::AccountId> for Module<T>
{
    fn is_dead_account(who: &T::AccountId) -> bool {
        unimplemented!();
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use runtime_io::with_externalities;
    use support::{impl_outer_origin, assert_ok};
    use primitives::{H256, Blake2Hasher};
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256, IdentityLookup},
        testing::{Digest, DigestItem, Header}
    };
    use zprimitives::{Ciphertext, SigVerificationKey, PreparedVk};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
    use pairing::Field;
    use hex_literal::{hex, hex_impl};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};

    const PK_PATH: &str = "../../zface/tests/proving.dat";
    const VK_PATH: &str = "../../zface/tests/verification.dat";

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    // For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`Test`) which `impl`s each of the
	// configuration traits of modules we want to use.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;

    impl system::Trait for Test {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Digest = Digest;
        type AccountId = SigVerificationKey;
        type SigVerificationKey = u64;
        type Lookup = IdentityLookup<SigVerificationKey>;
        type Header = Header;
        type Event = ();
        type Log = DigestItem;
    }

    impl Trait for Test {
        type Event = ();
    }

    impl zk_system::Trait for Test { }

    type EncryptedBalances = Module<Test>;

    fn alice_balance_init() -> (EncKey, Ciphertext) {
        let (alice_seed, enc_key) = get_alice_seed_ek();
        let alice_amount = 100 as u32;
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

        // The default balance is not encrypted with randomness.
        let enc_alice_bal = elgamal::Ciphertext::encrypt(
            alice_amount,
            &fs::Fs::one(),
            &enc_key,
            p_g,
            params
        );

        let decryption_key = ProofGenerationKey::<Bls12>::from_seed(&alice_seed[..], params).into_decryption_key().unwrap();

        let dec_alice_bal = enc_alice_bal.decrypt(&decryption_key, p_g, params).unwrap();
        assert_eq!(dec_alice_bal, alice_amount);

        (EncKey::from_encryption_key(&enc_key), Ciphertext::from_ciphertext(&enc_alice_bal))
    }

    fn alice_epoch_init() -> (EncKey, u64) {
        let (_, enc_key) = get_alice_seed_ek();

        (EncKey::from_encryption_key(&enc_key), 0)
    }

    fn get_alice_seed_ek() -> (Vec<u8>, EncryptionKey<Bls12>) {
        let params = &JubjubBls12::new();
        let alice_seed = b"Alice                           ".to_vec();

        (alice_seed.clone(), EncryptionKey::<Bls12>::from_seed(&alice_seed[..], params)
            .expect("should be generated encryption key from seed."))
    }

    pub fn get_pvk() -> PreparedVk {
        let vk_path = Path::new("../../zface/tests/verification.dat");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVk::from_slice(&buf_vk[..])
    }

    fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
        let (mut t, mut c) = system::GenesisConfig::<Test>::default().build_storage().unwrap();
        let _ = zk_system::GenesisConfig::<Test>{
            last_epoch: 1,
            epoch_length: 1,
            verifying_key: get_pvk(),
            nonce_pool: vec![],
        }.assimilate_storage(&mut t, &mut c);

        let _ = GenesisConfig::<Test>{
            encrypted_balance: vec![alice_balance_init()],
			last_rollover: vec![alice_epoch_init()],
            transaction_base_fee: 1,
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);

        t.into()
    }

    #[test]
    fn test_call_from_zface() {
        use rand::{SeedableRng, XorShiftRng};
        use test_pairing::{bls12_381::Bls12 as tBls12, Field as tField};
        use test_proofs::{EncryptionKey as tEncryptionKey, SpendingKey as tSpendingKey,
            elgamal as telgamal, PARAMS, MultiEncKeys, KeyContext, ProofBuilder, Confidential,
        };
        use scrypto::jubjub::{FixedGenerators as tFixedGenerators, fs::Fs as tFs, edwards as tedwards};

        with_externalities(&mut new_test_ext(), || {
            let alice_seed = b"Alice                           ".to_vec();
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let bob_addr: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let recipient_account_id = tEncryptionKey::<tBls12>::read(&mut &bob_addr[..], &PARAMS).unwrap();

            let spending_key = tSpendingKey::<tBls12>::from_seed(&alice_seed);

            let current_balance = 100;
            let remaining_balance = 91;
            let amount = 8;
            let fee = 1;

            let enc_key = tEncryptionKey::<tBls12>::from_seed(&alice_seed[..], &PARAMS).unwrap();
            let p_g = tFixedGenerators::NoteCommitmentRandomness;

            // The default balance is not encrypted with randomness.
            let enc_alice_bal = telgamal::Ciphertext::encrypt(
                current_balance,
                &tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            );

            let g_epoch_vec: [u8; 32] = hex!("0953f47325251a2f479c25527df6d977925bebafde84423b20ae6c903411665a");
            let g_epoch = tedwards::Point::read(&g_epoch_vec[..], &*PARAMS).unwrap().as_prime_order(&*PARAMS).unwrap();

            let tx = KeyContext::read_from_path(PK_PATH, VK_PATH)
                .unwrap()
                .gen_proof(
                    amount,
                    fee,
                    remaining_balance,
                    &spending_key,
                    MultiEncKeys::<tBls12, Confidential>::new(recipient_account_id),
                    &enc_alice_bal,
                    g_epoch,
                    rng,
                    &*PARAMS
                ).unwrap();

            assert_ok!(EncryptedBalances::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                Proof::from_slice(&tx.proof[..]),
                EncKey::from_slice(&tx.enc_key_sender[..]),
                EncKey::from_slice(&tx.enc_key_recipient[..]),
                LeftCiphertext::from_slice(&tx.left_amount_sender[..]),
                LeftCiphertext::from_slice(&tx.left_amount_recipient[..]),
                LeftCiphertext::from_slice(&tx.left_fee[..]),
                RightCiphertext::from_slice(&tx.right_randomness[..]),
                Nonce::from_slice(&tx.nonce[..])
            ));
        })
    }

    #[test]
    fn test_call_function() {
        with_externalities(&mut new_test_ext(), || {
            // Needed to be updated manually once snark paramters are pre-processed.
            let proof: [u8; 192] = hex!("b8a16f1610fccca19fc5264d337aa699473e2786e8fa47c3b63e7417885d2ad52f9a3d0999e09d25ef49164dd46f23f7b5cbfb28f0924d60fc29e855609a4d2400f9a2945de73d42d4c15e8e1eef7b81283144b947c20df217efd9aec230571307d92007b6dbfe3656ddae3fdd49cda3f5e31493085ea00ef845329e893efaaa8734f91adc38a8324e5dd52143b954ac93129a629592e681dea7399e48543594a3e94f7ea9dbaa88ed62dcd7b56d0916a396daa9ee2756dae581066ed9074521");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 32] = hex!("7a161216ec4a4102a09c81c69a09641c4fbd5e5907307dd59550eb1a636a2dcb");
            let enc10_by_bob: [u8; 32] = hex!("4b45499ed39b8e26fc3b41a6d2c0a0fd63a596844d9dc9312dd7f86d0499ae14");
            let enc1_by_alice: [u8; 32] = hex!("01570bd52d375bb97984bd92ffd3f18685d022f11f4e9b85ff815940f37ad637");
            let randomness: [u8; 32] = hex!("5f5261b09d5faf1775052226d539a18045592ccf711c0292e104a4ea5bd5c4eb");
            let rvk: [u8; 32] = hex!("fa8e6fbf6d2116ef083670d6859da118c662b97c4fabe6eacf7c6dc0b2953346");
            let nonce: [u8; 32] = hex!("c3427a3e3e9f19ff730d45c7c7daa1ee3c96b10a86085d11647fe27d923d654e");

            assert_ok!(EncryptedBalances::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&rvk[..])),
                Proof::from_slice(&proof[..]),
                EncKey::from_slice(&pkd_addr_alice),
                EncKey::from_slice(&pkd_addr_bob),
                LeftCiphertext::from_slice(&enc10_by_alice[..]),
                LeftCiphertext::from_slice(&enc10_by_bob[..]),
                LeftCiphertext::from_slice(&enc1_by_alice[..]),
                RightCiphertext::from_slice(&randomness[..]),
                Nonce::from_slice(&nonce[..])
            ));
        })
    }

    #[test]
    #[should_panic]
    fn test_call_with_worng_proof() {
        with_externalities(&mut new_test_ext(), || {
            let proof: [u8; 192] = hex!("c8a16f1610fccca19fc5264d337aa699473e2786e8fa47c3b63e7417885d2ad52f9a3d0999e09d25ef49164dd46f23f7b5cbfb28f0924d60fc29e855609a4d2400f9a2945de73d42d4c15e8e1eef7b81283144b947c20df217efd9aec230571307d92007b6dbfe3656ddae3fdd49cda3f5e31493085ea00ef845329e893efaaa8734f91adc38a8324e5dd52143b954ac93129a629592e681dea7399e48543594a3e94f7ea9dbaa88ed62dcd7b56d0916a396daa9ee2756dae581066ed9074521");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 32] = hex!("7a161216ec4a4102a09c81c69a09641c4fbd5e5907307dd59550eb1a636a2dcb");
            let enc10_by_bob: [u8; 32] = hex!("4b45499ed39b8e26fc3b41a6d2c0a0fd63a596844d9dc9312dd7f86d0499ae14");
            let enc1_by_alice: [u8; 32] = hex!("01570bd52d375bb97984bd92ffd3f18685d022f11f4e9b85ff815940f37ad637");
            let randomness: [u8; 32] = hex!("5f5261b09d5faf1775052226d539a18045592ccf711c0292e104a4ea5bd5c4eb");
            let rvk: [u8; 32] = hex!("fa8e6fbf6d2116ef083670d6859da118c662b97c4fabe6eacf7c6dc0b2953346");
            let nonce: [u8; 32] = hex!("c3427a3e3e9f19ff730d45c7c7daa1ee3c96b10a86085d11647fe27d923d654e");

            assert_ok!(EncryptedBalances::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&rvk[..])),
                Proof::from_slice(&proof[..]),
                EncKey::from_slice(&pkd_addr_alice),
                EncKey::from_slice(&pkd_addr_bob),
                LeftCiphertext::from_slice(&enc10_by_alice[..]),
                LeftCiphertext::from_slice(&enc10_by_bob[..]),
                LeftCiphertext::from_slice(&enc1_by_alice[..]),
                RightCiphertext::from_slice(&randomness[..]),
                Nonce::from_slice(&nonce[..])
            ));
        })
    }
}
