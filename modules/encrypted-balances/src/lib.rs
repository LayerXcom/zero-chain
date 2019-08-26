//! A module for dealing with confidential transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result};
use rstd::{
    prelude::*,
    result,
};
use runtime_primitives::traits::Zero;
use zprimitives::{
    EncKey, Proof, Nonce, RightCiphertext, LeftCiphertext, Ciphertext,
};
use system::{IsDeadAccount, ensure_signed};

pub trait Trait: system::Trait + zk_system::Trait {
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

            // Rollover and get sender's balance.
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            Self::rollover(&address_sender)?;

            // Rollover and get recipient's balance
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            Self::rollover(&address_recipient)?;

            // Veridate the provided nonce isn't included in the nonce pool.
            assert!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce));

            // Verify the zk proof
            if !<zk_system::Module<T>>::validate_confidential_proof(
                    &zkproof,
                    &address_sender,
                    &address_recipient,
                    &amount_sender,
                    &amount_recipient,
                    &Self::encrypted_balance(address_sender).map_or(Ciphertext::zero(), |e| e),
                    &rvk,
                    &fee_sender,
                    &randomness,
                    &nonce
                )? {
                    Self::deposit_event(RawEvent::InvalidZkProof());
                    return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            // Subtracting transferred amount and fee from the sender's encrypted balances.
            // This function causes a storage mutation.
            Self::sub_enc_balance(&address_sender, &amount_sender, &fee_sender, &randomness)
                .map_err(|_| "Faild to subtract amount from sender's balance.")?;

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(&address_recipient, &amount_recipient, &randomness)
                .map_err(|_| "Faild to add amount to recipient's pending_transfer.")?;

            Self::deposit_event(
                RawEvent::ConfidentialTransfer(
                    zkproof,
                    address_sender,
                    address_recipient,
                    amount_sender,
                    amount_recipient,
                    fee_sender,
                    randomness,
                    Self::encrypted_balance(address_sender).map_or(Ciphertext::zero(), |e| e),
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
    // PUBLIC MUTABLES

    /// Rolling over allows us to send transactions asynchronously and protect from front-running attacks.
    /// We rollover an account in an epoch when the first message from this account is received;
    /// so, one message rolls over only one account.
    /// To achieve this, we define a separate (internal) method for rolling over,
    /// and the first thing every other method does is to call this method.
    /// More details in Section 3.1: https://crypto.stanford.edu/~buenz/papers/zether.pdf
    pub fn rollover(addr: &EncKey) -> result::Result<(), &'static str> {
        let current_epoch = <zk_system::Module<T>>::get_current_epoch();

        let last_rollover = Self::last_rollover(addr)
            .map_or(T::BlockNumber::zero(), |e| e);

        // Get balance with the type
        let enc_pending_transfer = Self::pending_transfer(addr)
            .map_or(Ciphertext::zero(), |e| e);

        // Checks if the last roll over was in an older epoch.
        // If so, some storage changes are happend here.
        if last_rollover < current_epoch {
            // transfer balance from pending_transfer to actual balance
            <EncryptedBalance<T>>::mutate(addr, |balance| {
                let new_balance = match balance.clone() {
                    Some(b) => b.add(&enc_pending_transfer),
                    None => Ok(enc_pending_transfer),
                };

                match new_balance {
                    Ok(nb) => *balance = Some(nb),
                    Err(_) => return Err("Faild to mutate encrypted balance."),
                }

                Ok(())
            })?;

            // Reset pending_transfer.
            <PendingTransfer<T>>::remove(addr);
            // Set last rollover to current epoch.
            <LastRollOver<T>>::insert(addr, current_epoch);
        }
        // Initialize a nonce pool
        <zk_system::Module<T>>::init_nonce_pool(current_epoch);

        Ok(())
    }

    // Subtracting transferred amount and fee from encrypted balances.
    pub fn sub_enc_balance(
        address: &EncKey,
        amount: &LeftCiphertext,
        fee: &LeftCiphertext,
        randomness: &RightCiphertext
    ) -> result::Result<(), &'static str> {
        let enc_amount = Ciphertext::from_left_right(*amount, *randomness)
            .map_err(|_| "Faild to create amount ciphertext.")?;
        let enc_fee = Ciphertext::from_left_right(*fee, *randomness)
            .map_err(|_| "Faild to create fee ciphertext.")?;
        let amount_plus_fee = enc_amount.add(&enc_fee)
            .map_err(|_| "Failed to add fee to amount")?;

        <EncryptedBalance<T>>::mutate(address, |balance| {
            let new_balance = balance.clone()
                .and_then(
                    |b| b.sub(&amount_plus_fee).ok()
            );

            *balance = new_balance
        });

        Ok(())
    }

    /// Adding transferred amount to pending transfer.
    pub fn add_pending_transfer(
        address: &EncKey,
        amount: &LeftCiphertext,
        randomness: &RightCiphertext
    ) -> result::Result<(), &'static str> {
        let enc_amount = Ciphertext::from_left_right(*amount, *randomness)
            .map_err(|_| "Faild to create amount ciphertext.")?;

        <PendingTransfer<T>>::mutate(address, |pending_transfer| {
            let new_pending_transfer = match pending_transfer.clone() {
                Some(p) => p.add(&enc_amount),
                None => Ok(enc_amount),
            };

            match new_pending_transfer {
                Ok(np) => *pending_transfer = Some(np),
                Err(_) => return Err("Faild to mutate pending transfer.")
            }

            Ok(())
        })?;

        Ok(())
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
    use pairing::{Field, bls12_381::Bls12};
    use zcrypto::elgamal;
    use hex_literal::{hex, hex_impl};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::convert::TryFrom;

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

        (EncKey::try_from(enc_key).unwrap(), Ciphertext::try_from(enc_alice_bal).unwrap())
    }

    fn alice_epoch_init() -> (EncKey, u64) {
        let (_, enc_key) = get_alice_seed_ek();

        (EncKey::try_from(enc_key).unwrap(), 0)
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

            // G_epoch of block height one.
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
            let proof: [u8; 192] = hex!("95dbee00db7a61a907185f119b971341121faa9475271aca69a12d3f6fbb2705e5b516acb8902858a85553f4e082e09cb95497330dd3f9c79a36eed0275b3c5ded36fb53cb15f59a294ff9797b6df03f3e524fe503fec29baba2ff3b2a092541160c83778947f62e79419e3b8cb81a99eb52247e272d688622daddfc77f97acc0e29b0bc64f4d6c03114f0ae85643b12b035715b6acc34e6c2308c5678379fbe9fb0a74c9290bdde3298586a7a7283a37dfa025200c21ab08bfd7ae110d5b703");
            let pkd_addr_alice: [u8; 32] = hex!("fd0c0c0183770c99559bf64df4fe23f77ced9b8b4d02826a282bcd125117dcc2");
            let pkd_addr_bob: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc10_by_alice: [u8; 32] = hex!("63946e72576a843711d583dd18cc328923da5cacae709809669eafd56fae7889");
            let enc10_by_bob: [u8; 32] = hex!("159fe720e918b19dab20d188a04cd62231066087f576c550c0366aa68d0cb4a0");
            let enc1_by_alice: [u8; 32] = hex!("f607d32c536d9f6c2472291a290de335ce682a636a5d26b251f49d350b124343");
            let randomness: [u8; 32] = hex!("4037d0ddf22f9d09d335be087ff492ab6815c996817512458b2be26614eea455");
            let rvk: [u8; 32] = hex!("99d8d24c3b4610392c9a54259caad3bd9b987591313b52990db9f459c5b4addf");
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
