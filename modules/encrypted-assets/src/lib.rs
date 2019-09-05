//! A module for dealing with encrypted fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, Parameter, StorageValue, ensure};
use rstd::prelude::*;
use rstd::result;
use runtime_primitives::traits::{SimpleArithmetic, Zero, One, As};
use system::ensure_signed;
use zprimitives::{
    EncKey, Proof,
    Nonce, Ciphertext, LeftCiphertext, RightCiphertext,
};

/// The module configuration trait.
pub trait Trait: system::Trait + encrypted_balances::Trait + zk_system::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The arithmetic type of asset identifier.
    type AssetId: Parameter + SimpleArithmetic + Default + Copy;
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event<T>() = default;

        /// Issue a new class of encrypted fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `issuer` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
        fn issue(
            origin,
            zkproof: Proof,
            issuer: EncKey,
            total: LeftCiphertext,
            fee: LeftCiphertext,
            balance: Ciphertext,
            randomness: RightCiphertext,
            nonce: Nonce
        ) {
            let rvk = ensure_signed(origin)?;

            // Initialize a nonce pool
            let current_epoch = <zk_system::Module<T>>::get_current_epoch();
            <zk_system::Module<T>>::init_nonce_pool(current_epoch);

            // Veridate the provided nonce isn't included in the nonce pool.
            assert!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce)); // TODO: use ensure!

            // Verify a zk proof
            // 1. Spend authority verification
            // 2. Range check of issued amount
            // 3. Encryption integrity
            if !<zk_system::Module<T>>::verify_confidential_proof(
                &zkproof,
                &issuer,
                &issuer,
                &total,
                &total,
                &balance,
                &rvk,
                &fee,
                &randomness,
                &nonce
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            let id = Self::next_asset_id();
            <NextAssetId<T>>::mutate(|id| *id += One::one());

            let total_ciphertext = Ciphertext::from_left_right(total, randomness)
                .map_err(|_| "Faild to create ciphertext from left and right.")?;
            <EncryptedBalance<T>>::insert((id, issuer.clone()), total_ciphertext.clone());
            <TotalSupply<T>>::insert(id, total_ciphertext.clone());

            Self::deposit_event(RawEvent::Issued(id, issuer, total_ciphertext));
        }

        /// Move some encrypted assets from one holder to another.
        fn confidential_transfer(
            origin,
            asset_id: T::AssetId,
            zkproof: Proof,
            address_sender: EncKey,
            address_recipient: EncKey,
            amount_sender: LeftCiphertext,
            amount_recipient: LeftCiphertext,
            fee_sender: LeftCiphertext,
            randomness: RightCiphertext,
            nonce: Nonce
        ) {
            let rvk = ensure_signed(origin)?;

            runtime_io::print("before g_epoch");
            runtime_io::print(<zk_system::Module<T>>::last_epoch().as_());
            runtime_io::print(<zk_system::Module<T>>::g_epoch().as_bytes());

            // Rollover and get sender's balance.
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            Self::rollover(&address_sender, asset_id)?;

            // Rollover and get recipient's balance
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            Self::rollover(&address_recipient, asset_id)?;

            // Veridate the provided nonce isn't included in the nonce pool.
            ensure!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce), "Provided nonce is already included in the nonce pool.");

            runtime_io::print("after g_epoch");
            runtime_io::print(<zk_system::Module<T>>::last_epoch().as_());
            runtime_io::print(<zk_system::Module<T>>::g_epoch().as_bytes());

            // Verify the zk proof
            if !<zk_system::Module<T>>::verify_confidential_proof(
                &zkproof,
                &address_sender,
                &address_recipient,
                &amount_sender,
                &amount_recipient,
                &Self::encrypted_balance((asset_id, address_sender)).map_or(Ciphertext::zero(), |e| e),
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
            Self::sub_enc_balance(
                &address_sender,
                asset_id,
                &amount_sender,
                &fee_sender,
                &randomness
            )
            .map_err(|_| "Faild to subtract amount from sender's balance.")?;

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(
                &address_recipient,
                asset_id,
                &amount_recipient,
                &randomness
            )
            .map_err(|_| "Faild to add amount to recipient's pending_transfer.")?;

            Self::deposit_event(
                RawEvent::ConfidentialAssetTransferred(
                    asset_id, zkproof, address_sender, address_recipient,
                    amount_sender, amount_recipient, fee_sender, randomness,
                    Self::encrypted_balance((asset_id, address_sender)).map_or(Ciphertext::zero(), |e| e),
                    rvk
                )
            );
        }

        /// Destroy any encrypted assets of `id` owned by `owner`.
        fn destroy(
            origin,
            zkproof: Proof,
            owner: EncKey,
            id: T::AssetId,
            dummy_amount: LeftCiphertext,
            dummy_fee: LeftCiphertext,
            dummy_balance: Ciphertext,
            randomness: RightCiphertext,
            nonce: Nonce
        ) {
            let rvk = ensure_signed(origin)?;

            // Initialize a nonce pool
            let current_epoch = <zk_system::Module<T>>::get_current_epoch();
            <zk_system::Module<T>>::init_nonce_pool(current_epoch);

            // Veridate the provided nonce isn't included in the nonce pool.
            ensure!(!<zk_system::Module<T>>::nonce_pool().contains(&nonce), "Provided nonce is already included in the nonce pool.");

            // Verify the zk proof
            // 1. Spend authority verification
            if !<zk_system::Module<T>>::verify_confidential_proof(
                &zkproof,
                &owner,
                &owner,
                &dummy_amount,
                &dummy_amount,
                &dummy_balance,
                &rvk,
                &dummy_fee,
                &randomness,
                &nonce
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            // Add a nonce into the nonce pool
            <zk_system::Module<T>>::nonce_pool().push(nonce);

            let balance = <EncryptedBalance<T>>::take((id, owner.clone()))
                .map_or(Default::default(), |e| e);

            let pending_transfer = <PendingTransfer<T>>::take((id, owner.clone()))
                .map_or(Default::default(), |e| e);

            Self::deposit_event(RawEvent::Destroyed(id, owner, balance, pending_transfer));
        }
    }
}

decl_event!(
    pub enum Event<T>
    where
        <T as Trait>::AssetId,
        <T as system::Trait>::AccountId
    {
        /// Some encrypted assets were issued.
        Issued(AssetId, EncKey, Ciphertext),
        /// Some encrypted assets were transferred.
        ConfidentialAssetTransferred(
            AssetId, Proof, EncKey, EncKey, LeftCiphertext,
            LeftCiphertext, LeftCiphertext, RightCiphertext, Ciphertext, AccountId
        ),
        /// Some encrypted assets were destroyed.
        Destroyed(AssetId, EncKey, Ciphertext, Ciphertext),
        InvalidZkProof(),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedAssets {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map (T::AssetId, EncKey) => Option<Ciphertext>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map (T::AssetId, EncKey) => Option<Ciphertext>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map (T::AssetId, EncKey) => Option<T::BlockNumber>;

        /// The next asset identifier up for grabs.
        pub NextAssetId get(next_asset_id): T::AssetId;

        /// The total unit supply of an asset.
        pub TotalSupply: map T::AssetId => Ciphertext;
    }
}

impl<T: Trait> Module<T> {
    // PUBLIC MUTABLES

    /// Rolling over allows us to send transactions asynchronously and protect from front-running attacks.
    /// We rollover an account in an epoch when the first message from this account is received;
    /// so, one message rolls over only one account.
    /// To achieve this, we define a separate (internal) method for rolling over,
    /// and the first thing every other method does is to call this method.
    /// More details in Section 3.1: https://crypto.stanford.edu/~buenz/papers/zether.pdf
    pub fn rollover(addr: &EncKey, asset_id: T::AssetId) -> Result<(), &'static str> {
        let current_epoch = <zk_system::Module<T>>::get_current_epoch();
        let addr_id = (asset_id, *addr);

        let last_rollover = Self::last_rollover(addr_id)
            .map_or(T::BlockNumber::zero(), |e| e);

        // Get current pending transfer
        let enc_pending_transfer = Self::pending_transfer(addr_id)
            .map_or(Ciphertext::zero(), |e| e);

        // Checks if the last roll over was in an older epoch.
        // If so, some storage changes are happend here.
        if last_rollover < current_epoch {
            // transfer balance from pending_transfer to actual balance
            <EncryptedBalance<T>>::mutate(addr_id, |balance| {
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
            <PendingTransfer<T>>::remove(addr_id);
            // Set last rollover to current epoch.
            <LastRollOver<T>>::insert(addr_id, current_epoch);
        }
        // Initialize a nonce pool
        <zk_system::Module<T>>::init_nonce_pool(current_epoch);

        Ok(())
    }

    // Subtracting transferred amount and fee from encrypted balances.
    pub fn sub_enc_balance(
        address: &EncKey,
        asset_id: T::AssetId,
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

        <EncryptedBalance<T>>::mutate((asset_id, *address), |balance| {
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
        asset_id: T::AssetId,
        amount: &LeftCiphertext,
        randomness: &RightCiphertext
    ) -> result::Result<(), &'static str> {
        let enc_amount = Ciphertext::from_left_right(*amount, *randomness)
            .map_err(|_| "Faild to create amount ciphertext.")?;

        <PendingTransfer<T>>::mutate((asset_id, *address), |pending_transfer| {
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
    use zprimitives::{Ciphertext, SigVerificationKey};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
    use pairing::{Field, bls12_381::Bls12};
    use hex_literal::{hex, hex_impl};
    use rand::{SeedableRng, XorShiftRng};
    use test_pairing::{bls12_381::Bls12 as tBls12, Field as tField};
    use test_proofs::{EncryptionKey as tEncryptionKey, SpendingKey as tSpendingKey,
        elgamal as telgamal, PARAMS, MultiEncKeys, KeyContext, ProofBuilder, Confidential,
    };
    use scrypto::jubjub::{FixedGenerators as tFixedGenerators, fs::Fs as tFs, edwards as tedwards, PrimeOrder};
    use zcrypto::elgamal;
    use bellman_verifier::PreparedVerifyingKey;
    use std::{
        path::Path,
        fs::File,
        io::{BufReader, Read},
        convert::TryFrom,
    };

    const PK_PATH: &str = "../../zface/params/test_conf_pk.dat";
    const VK_PATH: &str = "../../zface/params/test_conf_vk.dat";

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

    impl encrypted_balances::Trait for Test {
        type Event = ();
    }

    impl zk_system::Trait for Test { }

    impl Trait for Test {
        type Event = ();
        type AssetId = u64;
    }

    type EncryptedAssets = Module<Test>;

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
        let balance_init = alice_balance_init();
        let epoch_init = alice_epoch_init();

        let (mut t, mut c) = system::GenesisConfig::<Test>::default().build_storage().unwrap();
        let _ = zk_system::GenesisConfig::<Test>{
            last_epoch: 1,
            epoch_length: 1,
            confidential_vk: get_conf_vk(),
            anonymous_vk: get_anony_vk(),
            nonce_pool: vec![],
        }.assimilate_storage(&mut t, &mut c);
        let _ = encrypted_balances::GenesisConfig::<Test>{
            encrypted_balance: vec![balance_init.clone()],
			last_rollover: vec![epoch_init],
            transaction_base_fee: 1,
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);
        let _ = GenesisConfig::<Test>{
            encrypted_balance: vec![((0, balance_init.0), balance_init.1)],
			last_rollover: vec![((0, epoch_init.0), epoch_init.1)],
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);

        t.into()
    }

    fn get_g_epoch() -> tedwards::Point<tBls12, PrimeOrder> {
        let g_epoch_vec: [u8; 32] = hex!("0953f47325251a2f479c25527df6d977925bebafde84423b20ae6c903411665a");
        let g_epoch = tedwards::Point::read(&g_epoch_vec[..], &*PARAMS).unwrap().as_prime_order(&*PARAMS).unwrap();
        g_epoch
    }

    #[test]
    fn test_issue_from_zface() {
        with_externalities(&mut new_test_ext(), || {
            let seed = b"Alice                           ".to_vec();
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let p_g = tFixedGenerators::NoteCommitmentRandomness;

            let spending_key = tSpendingKey::<tBls12>::from_seed(&seed);
            let enc_key = tEncryptionKey::from_seed(&seed[..], &*PARAMS).unwrap();

            let amount = 100;
            let enc_balance = vec![telgamal::Ciphertext::encrypt(
                amount,
                &tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            )];

            let tx = KeyContext::read_from_path(PK_PATH, VK_PATH)
                .unwrap()
                .gen_proof(
                    amount,
                    0,
                    0, 0, 0,
                    &spending_key,
                    MultiEncKeys::<tBls12, Confidential>::new(enc_key),
                    &enc_balance,
                    get_g_epoch(),
                    rng,
                    &*PARAMS
                ).unwrap();

            // System::set_block_number(10);

            assert_ok!(EncryptedAssets::issue(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                Proof::from_slice(&tx.proof[..]),
                EncKey::from_slice(&tx.enc_key_recipient[..]),
                LeftCiphertext::from_slice(&tx.left_amount_recipient[..]),
                LeftCiphertext::from_slice(&tx.left_fee[..]),
                Ciphertext::from_slice(&tx.enc_balance[..]),
                RightCiphertext::from_slice(&tx.right_randomness[..]),
                Nonce::from_slice(&tx.nonce[..])
            ));
        })
    }

    #[test]
    fn test_confidential_transfer_from_zface() {
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
            let enc_alice_bal = vec![telgamal::Ciphertext::encrypt(
                current_balance,
                &tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            )];

            let tx = KeyContext::read_from_path(PK_PATH, VK_PATH)
                .unwrap()
                .gen_proof(
                    amount,
                    fee,
                    remaining_balance, 0, 0,
                    &spending_key,
                    MultiEncKeys::<tBls12, Confidential>::new(recipient_account_id),
                    &enc_alice_bal,
                    get_g_epoch(),
                    rng,
                    &*PARAMS
                ).unwrap();

            assert_ok!(EncryptedAssets::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                0,
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
    fn test_destroy_from_zface() {
        with_externalities(&mut new_test_ext(), || {
            let alice_seed = b"Alice                           ".to_vec();
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

            let spending_key = tSpendingKey::<tBls12>::from_seed(&alice_seed);
            let enc_key = tEncryptionKey::<tBls12>::from_seed(&alice_seed[..], &PARAMS).unwrap();
            let p_g = tFixedGenerators::NoteCommitmentRandomness;

            let dummy_balance  = vec![telgamal::Ciphertext::encrypt(
                0,
                &tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            )];

            let tx = KeyContext::read_from_path(PK_PATH, VK_PATH)
                .unwrap()
                .gen_proof(
                    0,
                    0,
                    0, 0, 0,
                    &spending_key,
                    MultiEncKeys::<tBls12, Confidential>::new(enc_key),
                    &dummy_balance,
                    get_g_epoch(),
                    rng,
                    &*PARAMS
                ).unwrap();

            assert_ok!(EncryptedAssets::destroy(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                Proof::from_slice(&tx.proof[..]),
                EncKey::from_slice(&tx.enc_key_recipient[..]),
                0,
                LeftCiphertext::from_slice(&tx.left_amount_recipient[..]),
                LeftCiphertext::from_slice(&tx.left_fee[..]),
                Ciphertext::from_slice(&tx.enc_balance[..]),
                RightCiphertext::from_slice(&tx.right_randomness[..]),
                Nonce::from_slice(&tx.nonce[..])
            ));

        })
    }
}
