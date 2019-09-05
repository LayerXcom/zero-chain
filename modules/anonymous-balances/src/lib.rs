//! A module for dealing with anonymous transfer
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure};
use rstd::{
    prelude::*,
    result,
};
use runtime_primitives::traits::Zero;
use zprimitives::{EncKey, Proof, Nonce, RightCiphertext, LeftCiphertext, Ciphertext};
use system::ensure_signed;

pub trait Trait: system::Trait + zk_system::Trait + encrypted_balances::Trait {
    // The overarching event type.
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // Initializing events
		fn deposit_event<T>() = default;

        pub fn anonymous_transfer(
            origin,
            zkproof: Proof,
            enc_keys: Vec<EncKey>,
            left_ciphertexts: Vec<LeftCiphertext>,
            right_ciphertext: RightCiphertext,
            nonce: Nonce
        ) -> Result {
            ensure!(enc_keys.len() == left_ciphertexts.len(), "length should be equal");
            let rvk = ensure_signed(origin)?;

            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            for e in &enc_keys {
                Self::rollover(e)?;
            }

            // Veridate the provided nonce isn't included in the nonce pool.
            assert!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce));

            let mut acc = vec![];
            for c in &enc_keys {
                let tmp = Self::encrypted_balance(c).map_or(Ciphertext::zero(), |e| e);
                acc.push(tmp);
            }

            // Verify the zk proof
            if !<zk_system::Module<T>>::verify_anonymous_proof(
                    &zkproof,
                    &enc_keys[..],
                    &left_ciphertexts[..],
                    &right_ciphertext,
                    &acc[..],
                    &rvk,
                    &nonce
                )? {
                    Self::deposit_event(RawEvent::InvalidZkProof());
                    return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            for (e, c) in enc_keys.iter().zip(left_ciphertexts.iter()) {
                <encrypted_balances::Module<T>>::add_pending_transfer(e, c, &right_ciphertext)?;
            }

            Self::deposit_event(
                RawEvent::AnonymousTransfer(
                    zkproof,
                    enc_keys,
                    left_ciphertexts,
                    right_ciphertext,
                    rvk
                )
            );

            Ok(())
        }
    }
}

decl_storage! {
    trait Store for Module<T: Trait> as AnonymousBalances {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map EncKey => Option<Ciphertext>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map EncKey => Option<Ciphertext>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map EncKey => Option<T::BlockNumber>;

        // TODO: Change to BTreeSet once parity-codec is updated to parity-scale-codec
        pub EncKeySet get(enc_key_set) config() : Vec<EncKey>;
    }
}

decl_event! (
    /// An event in this module.
    pub enum Event<T> where <T as system::Trait>::AccountId {
        AnonymousTransfer(Proof, Vec<EncKey>, Vec<LeftCiphertext>, RightCiphertext, AccountId),
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
}

#[cfg(feature = "std")]
#[cfg(test)]
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rng};
    use runtime_io::with_externalities;
    use support::{impl_outer_origin, assert_ok};
    use primitives::{H256, Blake2Hasher};
    use runtime_primitives::{
        BuildStorage, traits::{BlakeTwo256, IdentityLookup},
        testing::{Digest, DigestItem, Header}
    };
    use zprimitives::{Ciphertext, SigVerificationKey, PARAMS as ZPARAMS};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
    use pairing::{Field, bls12_381::Bls12};
    use zcrypto::elgamal;
    use hex_literal::{hex, hex_impl};
    use bellman_verifier::PreparedVerifyingKey;
    use test_proofs::{EncryptionKey as tEncryptionKey, SpendingKey as tSpendingKey,
            elgamal as telgamal, PARAMS, MultiEncKeys, KeyContext, ProofBuilder,
            constants::ANONIMITY_SIZE, crypto_components::Anonymous,
        };
    use test_pairing::{bls12_381::Bls12 as tBls12, Field as tField};
    use scrypto::jubjub::{FixedGenerators as tFixedGenerators, fs::Fs as tFs, edwards as tedwards};
    use std::{
        path::Path,
        fs::File,
        io::{BufReader, Read},
        convert::TryFrom,
    };
    // use lazy_static::lazy;

    lazy_static! {
        pub static ref ANONY_BALANCES: Vec<(EncKey, Ciphertext)> = { init_anonymous_balances() };
        pub static ref ENC_KEYS: Vec<EncryptionKey<Bls12>> = { init_typed_enc_keys() };
    }

    const PK_PATH: &str = "../../zface/params/test_anony_pk.dat";
    const VK_PATH: &str = "../../zface/params/test_anony_vk.dat";

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
    impl encrypted_balances::Trait for Test {
        type Event = ();
    }
    type AnonymousBalances = Module<Test>;

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

    fn get_alice_enc_key() -> EncryptionKey<Bls12> {
        let params = &JubjubBls12::new();
        let alice_seed = b"Alice                           ".to_vec();
        let enc_key = EncryptionKey::<Bls12>::from_seed(&&alice_seed, params)
            .expect("should be generated encryption key from seed.");
        enc_key
    }

    fn get_bob_enc_key() -> EncryptionKey<Bls12> {
        let bob_addr: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
        let enc_key_recipient = EncryptionKey::<Bls12>::read(&mut &bob_addr[..], &ZPARAMS).unwrap();
        enc_key_recipient
    }

    fn init_typed_enc_keys() -> Vec<EncryptionKey<Bls12>> {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let mut acc = vec![];
        for _ in 0..10 {
            let random_seed: [u8; 32] = rng.gen();
            let enc_key = EncryptionKey::<Bls12>::from_seed(&random_seed, params)
                .expect("should be generated encryption key from seed.");
            acc.push(enc_key);
        }
        acc.insert(0, get_alice_enc_key());
        acc.insert(1, get_bob_enc_key());

        acc
    }

    fn init_anonymous_enc_keys() -> Vec<EncKey> {
        ENC_KEYS.clone().into_iter().map(|e| EncKey::try_from(e).unwrap()).collect::<Vec<EncKey>>()
    }

    fn get_enc_balances() -> Vec<telgamal::Ciphertext<tBls12>> {
        ANONY_BALANCES.clone().into_iter().map(|(_, c)| {
            let mut r = c.as_bytes();
            let c_1 = telgamal::Ciphertext::read(&mut r, &*PARAMS).unwrap();
            c_1
        }).collect()
    }

    fn init_anonymous_balances() -> Vec<(EncKey, Ciphertext)> {
        let params = &JubjubBls12::new();
        let alice_value = 10_000 as u32;
        let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

        let mut acc = vec![];
        for (i, e) in ENC_KEYS.iter().enumerate() {
            if i == 0 {
                let ciphertext = elgamal::Ciphertext::encrypt(alice_value, &fs::Fs::one(), &e, p_g, params);
                acc.push((EncKey::try_from(e.clone()).unwrap(), Ciphertext::try_from(ciphertext).unwrap()))
            } else {
                let ciphertext = elgamal::Ciphertext::encrypt(0, &fs::Fs::one(), e, p_g, params);
                acc.push((EncKey::try_from(e.clone()).unwrap(), Ciphertext::try_from(ciphertext).unwrap()))
            }
        }
        acc
    }

    pub fn get_conf_vk() -> PreparedVerifyingKey<Bls12> {
        let vk_path = Path::new("../../zface/params/test_conf_vk.dat");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap()
    }

    pub fn get_anony_vk() -> PreparedVerifyingKey<Bls12> {
        let vk_path = Path::new("../../zface/params/test_anony_vk.dat");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap()
    }

    fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
        let (mut t, mut c) = system::GenesisConfig::<Test>::default().build_storage().unwrap();
        let _ = zk_system::GenesisConfig::<Test>{
            last_epoch: 1,
            epoch_length: 1,
            confidential_vk: get_conf_vk(),
            anonymous_vk: get_anony_vk(),
            nonce_pool: vec![],
        }.assimilate_storage(&mut t, &mut c);

        let _ = encrypted_balances::GenesisConfig::<Test>{
            encrypted_balance: vec![alice_balance_init()],
			last_rollover: vec![alice_epoch_init()],
            transaction_base_fee: 1,
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);

        let _ = GenesisConfig::<Test>{
            encrypted_balance: ANONY_BALANCES.to_vec(),
			last_rollover: vec![alice_epoch_init()],
			enc_key_set: init_anonymous_enc_keys(),
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);

        t.into()
    }

    fn no_std_e(enc_key: &EncryptionKey<Bls12>) -> tEncryptionKey<tBls12> {
        let mut enc_key_vec = vec![];
        enc_key.write(&mut enc_key_vec).unwrap();
        let key = tEncryptionKey::<tBls12>::read(&mut &enc_key_vec[..], &*PARAMS).unwrap();
        key
    }

    #[test]
    fn test_call_from_zface() {

        with_externalities(&mut new_test_ext(), || {
            let alice_seed = b"Alice                           ".to_vec();
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

            let spending_key = tSpendingKey::<tBls12>::from_seed(&alice_seed);
            let bob_addr: [u8; 32] = hex!("45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389");
            let enc_key_recipient = tEncryptionKey::<tBls12>::read(&mut &bob_addr[..], &PARAMS).unwrap();

            let current_balance = 100;
            let remaining_balance = 91;
            let amount = 9;

            let enc_key_sender = tEncryptionKey::<tBls12>::from_seed(&alice_seed[..], &PARAMS).unwrap();
            let p_g = tFixedGenerators::NoteCommitmentRandomness;

            // G_epoch of block height one.
            let g_epoch_vec: [u8; 32] = hex!("0953f47325251a2f479c25527df6d977925bebafde84423b20ae6c903411665a");
            let g_epoch = tedwards::Point::read(&g_epoch_vec[..], &*PARAMS).unwrap().as_prime_order(&*PARAMS).unwrap();

            let s_index: usize = rng.gen_range(0, ANONIMITY_SIZE);
            let t_index: usize = rng.gen_range(0, ANONIMITY_SIZE);

            let decoys = ENC_KEYS.iter().take(10).map(|e| no_std_e(e)).collect();
            let enc_balances = get_enc_balances();

            let tx = KeyContext::read_from_path(PK_PATH, VK_PATH)
                .unwrap()
                .gen_proof(
                    amount,
                    0,
                    remaining_balance,
                    s_index,
                    t_index,
                    &spending_key,
                    MultiEncKeys::<tBls12, Anonymous>::new(enc_key_recipient, decoys),
                    &enc_balances,
                    g_epoch,
                    rng,
                    &*PARAMS
                ).unwrap();

            // assert_ok!(AnonymousBalances::anonymous_transfer(
            //     Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
            //     Proof::from_slice(&tx.proof[..]),
            //     EncKey::from_slice(&tx.e[..]),
            //     LeftCiphertext::from_slice(&tx.left_amount_sender[..]),
            //     LeftCiphertext::from_slice(&tx.left_amount_recipient[..]),
            //     LeftCiphertext::from_slice(&tx.left_fee[..]),
            //     RightCiphertext::from_slice(&tx.right_randomness[..]),
            //     Nonce::from_slice(&tx.nonce[..])
            // ));
        })
    }
}
