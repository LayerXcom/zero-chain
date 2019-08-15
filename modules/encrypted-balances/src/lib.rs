//! A module for dealing with confidential transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageValue, StorageMap, dispatch::Result, Parameter};
use rstd::prelude::*;
use rstd::result;
use rstd::convert::{TryFrom, TryInto};
use bellman_verifier::verify_proof;
use pairing::{
    bls12_381::{Bls12,Fr},
    Field,
};
use runtime_primitives::traits::{Member, Zero, MaybeSerializeDebug, As};
use jubjub::redjubjub::PublicKey;
use jubjub::curve::{edwards, PrimeOrder};
use zprimitives::{
    EncKey, Proof, PreparedVk, ElgamalCiphertext,
    SigVk, Nonce, GEpoch,
};
use parity_codec::Codec;
use keys::EncryptionKey;
use zcrypto::elgamal;
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait + zk_system::Trait {
	/// The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The units in which we record encrypted balances.
    type EncryptedBalance: ElgamalCiphertext + Parameter + Member + Default + MaybeSerializeDebug + Codec;
}

pub struct TypedParams {
    pub zkproof: bellman_verifier::Proof<Bls12>,
    pub address_sender: EncryptionKey<Bls12>,
    pub address_recipient: EncryptionKey<Bls12>,
    pub amount_sender: elgamal::Ciphertext<Bls12>,
    pub amount_recipient: elgamal::Ciphertext<Bls12>,
    pub rvk: PublicKey<Bls12>,
    pub fee_sender: elgamal::Ciphertext<Bls12>,
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
            amount_sender: T::EncryptedBalance,
            amount_recipient: T::EncryptedBalance,
            fee_sender: T::EncryptedBalance,
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
                &rvk,
                &fee_sender,
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
                    &typed.amount_sender,
                    &typed.amount_recipient,
                    &typed_balance_sender,
                    &typed.rvk,
                    &typed.fee_sender,
                    &nonce.try_into().map_err(|_| "Failed to convert from Nonce.")?
                )? {
                    Self::deposit_event(RawEvent::InvalidZkProof());
                    return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            // Subtracting transferred amount and fee from the sender's encrypted balances.
            // This function causes a storage mutation.
            Self::sub_enc_balance(&address_sender, &typed_balance_sender, &typed.amount_sender, &typed.fee_sender);

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(&address_recipient, &typed_balance_recipient, &typed.amount_recipient);

            Self::deposit_event(
                RawEvent::ConfidentialTransfer(
                    zkproof,
                    address_sender,
                    address_recipient,
                    amount_sender,
                    amount_recipient,
                    fee_sender,
                    T::EncryptedBalance::from_ciphertext(&typed_balance_sender),
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
        pub EncryptedBalance get(encrypted_balance) config() : map EncKey => Option<T::EncryptedBalance>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map EncKey => Option<T::EncryptedBalance>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map EncKey => Option<T::BlockNumber>;

        /// A fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config(): FeeAmount;
    }
}

decl_event! (
    /// An event in this module.
	pub enum Event<T> where <T as Trait>::EncryptedBalance, <T as system::Trait>::AccountId {
		ConfidentialTransfer(Proof, EncKey, EncKey, EncryptedBalance, EncryptedBalance, EncryptedBalance, EncryptedBalance, AccountId),
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
        amount_sender: &T::EncryptedBalance,
        amount_recipient: &T::EncryptedBalance,
        rvk: &T::AccountId,
        fee_sender: &T::EncryptedBalance,
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

        // Get amount_sender with the type
        let typed_amount_sender = amount_sender
            .into_ciphertext()
            .ok_or("Invalid amount_sender")?;

        // Get amount_recipient with the type
        let typed_amount_recipient = amount_recipient
            .into_ciphertext()
            .ok_or("Invalid amount_recipient")?;

        // Get fee_sender with the type
        let typed_fee_sender = fee_sender
            .into_ciphertext()
            .ok_or("Invalid fee_sender")?;

        // Get rvk with the type
        let typed_rvk = rvk
            .into_verification_key()
            .ok_or("Invalid rvk")?;

        Ok(TypedParams {
            zkproof: typed_zkproof,
            address_sender: typed_addr_sender,
            address_recipient: typed_addr_recipient,
            amount_sender: typed_amount_sender ,
            amount_recipient: typed_amount_recipient,
            rvk:typed_rvk,
            fee_sender: typed_fee_sender,
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
                    |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_pending_transfer)))
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
                |_| T::EncryptedBalance::from_ciphertext(&typed_balance.sub_no_params(&amount_plus_fee)));
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
                Some(T::EncryptedBalance::from_ciphertext(&typed_amount)),
                |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_amount)))
            );
            *pending_transfer = new_pending_transfer
        });
    }
}

impl<T: Trait> IsDeadAccount<T::AccountId> for Module<T>
where
    T::EncryptedBalance: MaybeSerializeDebug
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
    use zprimitives::{Ciphertext, SigVerificationKey};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
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
        type EncryptedBalance = Ciphertext;
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

        let _ = encrypted_balances::GenesisConfig::<Test>{
            encrypted_balance: vec![alice_balance_init()],
			last_rollover: vec![alice_epoch_init()],
            transaction_base_fee: 1,
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
                Ciphertext::from_slice(&tx.enc_amount_sender[..]),
                Ciphertext::from_slice(&tx.enc_amount_recipient[..]),
                Ciphertext::from_slice(&tx.enc_fee[..]),
                Nonce::from_slice(&tx.nonce[..])
            ));
        })
    }

    #[test]
    fn test_call_function() {
        with_externalities(&mut new_test_ext(), || {
            // Needed to be updated manually once snark paramters are pre-processed.
            let proof: [u8; 192] = hex!("884522462f65dd2e99a38f1d836d065a452f16cfe08b45cd22d272a622c3ab954180a3fa8bf08053058062ad2ced8e3cae1a7a331dab872730261b0c86dba8fdb1bddab2c157450a39bd7362f57ff4018e24024441d48932e4a6a2a2b21a3db2027ce48f611651a394c8ee4f0a822705daa68048ef909b9b4860c9fe94c59cdfaed7ad3ee6c8c9e24340f35cd3d2376a8d98e54c755de29d05e87a0478908dcd697c8a9f78e0b6fa868b35ae618d138e55df4ec04e0a56fdb92eac927ca71d54");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 64] = hex!("1cddb561acaccaecb08c8ac6e2e8f5ce5538eb3fab99aa4795286534faf7e381942d999c2e7ffd124a09e78c6ec5b97219f7b06903aff6e121fe4b0cc97ccc6b");
            let enc10_by_bob: [u8; 64] = hex!("614e76c8f3795c38bfcbf8e5b9531aaa3d1f7f419d0066f218f10ae5a27e8b1b942d999c2e7ffd124a09e78c6ec5b97219f7b06903aff6e121fe4b0cc97ccc6b");
            let enc1_by_alice: [u8; 64] = hex!("0e282adf4d7c0dabd034a6e93479c314941d1ac3f52434d651b9dc64404abcbc942d999c2e7ffd124a09e78c6ec5b97219f7b06903aff6e121fe4b0cc97ccc6b");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let nonce: [u8; 32] = hex!("c3427a3e3e9f19ff730d45c7c7daa1ee3c96b10a86085d11647fe27d923d654e");

            assert_ok!(EncryptedBalances::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&rvk[..])),
                Proof::from_slice(&proof[..]),
                EncKey::from_slice(&pkd_addr_alice),
                EncKey::from_slice(&pkd_addr_bob),
                Ciphertext::from_slice(&enc10_by_alice[..]),
                Ciphertext::from_slice(&enc10_by_bob[..]),
                Ciphertext::from_slice(&enc1_by_alice[..]),
                Nonce::from_slice(&nonce[..])
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
            let enc1_by_alice: [u8; 64] = hex!("ed19f1820c3f09da976f727e8531aa83a483d262e4abb1e9e67a1eba843b4034b8b965029e45bd78aabe14c66458dd03f138aa8b58490974f23aabb53d9bce99");
            let rvk: [u8; 32] = hex!("f539db3c0075f6394ff8698c95ca47921669c77bb2b23b366f42a39b05a88c96");
            let nonce: [u8; 32] = hex!("c3427a3e3e9f19ff730d45c7c7daa1ee3c96b10a86085d11647fe27d923d654e");

            assert_ok!(EncryptedBalances::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&rvk[..])),
                Proof::from_slice(&proof[..]),
                EncKey::from_slice(&pkd_addr_alice),
                EncKey::from_slice(&pkd_addr_bob),
                Ciphertext::from_slice(&enc10_by_alice[..]),
                Ciphertext::from_slice(&enc10_by_bob[..]),
                Ciphertext::from_slice(&enc1_by_alice[..]),
                Nonce::from_slice(&nonce[..])
            ));
        })
    }
}
