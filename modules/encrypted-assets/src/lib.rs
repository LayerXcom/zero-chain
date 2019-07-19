//! A module for dealing with encrypted fungible assets.

// Ensure we're `no_std` when compiling for Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use support::{decl_module, decl_storage, decl_event, StorageMap, dispatch::Result, ensure, Parameter, StorageValue};
use rstd::prelude::*;
use rstd::result;
use parity_codec::Codec;
use runtime_primitives::traits::{Member, SimpleArithmetic, Zero, One, StaticLookup, MaybeSerializeDebug};
use system::ensure_signed;
use zprimitives::{
    PkdAddress,
    Proof,
    Ciphertext,
    SigVerificationKey,
    ElgamalCiphertext,
    SigVk,
};
use jubjub::redjubjub::PublicKey;
use keys::EncryptionKey;
use zcrypto::elgamal;
use pairing::bls12_381::Bls12;
use encrypted_balances;

/// The module configuration trait.
pub trait Trait: system::Trait + encrypted_balances::Trait {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

    /// The arithmetic type of asset identifier.
    type AssetId: Parameter + SimpleArithmetic + Default + Copy;
}

struct TypedParams {
    zkproof: bellman_verifier::Proof<Bls12>,
    issuer: EncryptionKey<Bls12>,
    total: elgamal::Ciphertext<Bls12>,
    rvk: PublicKey<Bls12>,
    dummy_fee: elgamal::Ciphertext<Bls12>,
    dummy_balance: elgamal::Ciphertext<Bls12>,
}

type FeeAmount = u32;

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event<T>() = default;

        /// Issue a new class of encrypted fungible assets. There are, and will only ever be, `total`
		/// such assets and they'll all belong to the `issuer` initially. It will have an
		/// identifier `AssetId` instance: this will be specified in the `Issued` event.
        fn issue(
            origin,
            zkproof: Proof,
            issuer: PkdAddress,
            total: T::EncryptedBalance,
            fee: T::EncryptedBalance,
            balance: T::EncryptedBalance
        ) {
            let rvk = ensure_signed(origin)?;

            // Convert provided parametrs into typed ones.
            let typed = Self::into_types(
                &zkproof,
                &issuer,
                &total,
                &rvk,
                &fee,
                &balance
            )
            .map_err(|_| "Failed to convert into types.")?;

            // let zero = elgamal::Ciphertext::zero();

            // Verify a zk proof
            // 1. Spend authority verification
            // 2. Range proof of issued amount
            // 3. Encryption integrity
            if !<encrypted_balances::Module<T>>::validate_proof(
                &typed.zkproof,
                &typed.issuer,
                &typed.issuer,
                &typed.total,
                &typed.total,
                &typed.dummy_balance,
                &typed.rvk,
                &typed.dummy_fee,
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            let id = Self::next_asset_id();
            <NextAssetId<T>>::mutate(|id| *id += One::one());
            <EncryptedBalance<T>>::insert((id, issuer.clone()), total.clone());
            <TotalSupply<T>>::insert(id, total.clone());

            Self::deposit_event(RawEvent::Issued(id, issuer, total));
        }

        /// Move some encrypted assets from one holder to another.
        fn confidential_transfer(
            origin,
            asset_id: T::AssetId,
            zkproof: Proof,
            address_sender: PkdAddress,
            address_recipient: PkdAddress,
            amount_sender: T::EncryptedBalance,
            amount_recipient: T::EncryptedBalance,
            fee_sender: T::EncryptedBalance
        ) {
            let rvk = ensure_signed(origin)?;

            let typed = <encrypted_balances::Module<T>>::into_types(
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
            let typed_balance_sender = Self::rollover(&address_sender, asset_id)
                .map_err(|_| "Invalid ciphertext of sender balance.")?;

            // Rollover and get recipient's balance
            // This function causes a storage mutation, but it's needed before `verify_proof` function is called.
            // No problem if errors occur after this function because
            // it just rollover user's own `pending trasfer` to `encrypted balances`.
            let typed_balance_recipient = Self::rollover(&address_recipient, asset_id)
                .map_err(|_| "Invalid ciphertext of recipient balance.")?;

            // Verify the zk proof
            if !<encrypted_balances::Module<T>>::validate_proof(
                &typed.zkproof,
                &typed.address_sender,
                &typed.address_recipient,
                &typed.amount_sender,
                &typed.amount_recipient,
                &typed_balance_sender,
                &typed.rvk,
                &typed.fee_sender,
            )? {
                Self::deposit_event(RawEvent::InvalidZkProof());
                return Err("Invalid zkproof");
            }

            // Subtracting transferred amount and fee from the sender's encrypted balances.
            // This function causes a storage mutation.
            Self::sub_enc_balance(
                &address_sender,
                asset_id,
                &typed_balance_sender,
                &typed.amount_sender,
                &typed.fee_sender
            );

            // Adding transferred amount to the recipient's pending transfer.
            // This function causes a storage mutation.
            Self::add_pending_transfer(
                &address_recipient,
                asset_id,
                &typed_balance_recipient,
                &typed.amount_recipient
            );

            Self::deposit_event(
                RawEvent::ConfidentialAssetTransferred(
                    asset_id, zkproof, address_sender, address_recipient,
                    amount_sender, amount_recipient, fee_sender,
                    T::EncryptedBalance::from_ciphertext(&typed_balance_sender),
                    rvk
                )
            );
        }

        /// Destroy any encrypted assets of `id` owned by `owner`.
        fn destroy(
            origin,
            zkproof: Proof,
            owner: PkdAddress,
            id: T::AssetId
        ) {
            let origin = ensure_signed(origin)?;

            // TODO: Verifying zk proof

            // let balance = <EncryptedBalances<T>>::take((id, owner.clone()));

            // Self::deposit_event(RawEvent::Destroyed(id, owner, balance));

        }

    }
}

decl_event!(
    pub enum Event<T>
    where
        <T as Trait>::AssetId,
        <T as encrypted_balances::Trait>::EncryptedBalance,
        <T as system::Trait>::AccountId
    {
        /// Some encrypted assets were issued.
        Issued(AssetId, PkdAddress, EncryptedBalance),
        /// Some encrypted assets were transferred.
        ConfidentialAssetTransferred(
            AssetId, Proof, PkdAddress, PkdAddress, EncryptedBalance,
            EncryptedBalance, EncryptedBalance, EncryptedBalance, AccountId
        ),
        /// Some encrypted assets were destroyed.
        Destroyed(AssetId, PkdAddress, EncryptedBalance),
        InvalidZkProof(),
    }
);

decl_storage! {
    trait Store for Module<T: Trait> as EncryptedAssets {
        /// An encrypted balance for each account
        pub EncryptedBalance get(encrypted_balance) config() : map (T::AssetId, PkdAddress) => Option<T::EncryptedBalance>;

        /// A pending transfer
        pub PendingTransfer get(pending_transfer) : map (T::AssetId, PkdAddress) => Option<T::EncryptedBalance>;

        /// A last epoch for rollover
        pub LastRollOver get(last_rollover) config() : map (T::AssetId, PkdAddress) => Option<T::BlockNumber>;

        /// Global epoch length for rollover.
        /// The longer epoch length is, the longer rollover time is.
        /// This parameter should be fixed based on trade-off between UX and security in terms of front-running attacks.
        pub EpochLength get(epoch_length) config() : map T::AssetId => T::BlockNumber;

        /// A fee to be paid for making a transaction; the base.
        pub TransactionBaseFee get(transaction_base_fee) config() : map T::AssetId => FeeAmount;

        /// The next asset identifier up for grabs.
        pub NextAssetId get(next_asset_id): T::AssetId;

        /// The total unit supply of an asset.
        pub TotalSupply: map T::AssetId => T::EncryptedBalance;
    }
}

impl<T: Trait> Module<T> {
    // PRIVATE IMMUTABLES

    fn into_types(
        zkproof: &Proof,
        issuer: &PkdAddress,
        total: &T::EncryptedBalance,
        rvk: &T::AccountId,
        fee: &T::EncryptedBalance,
        balance: &T::EncryptedBalance
    ) -> result::Result<TypedParams, &'static str>
    {
        // Get zkproofs with the type
        let typed_zkproof = zkproof
            .into_proof()
            .ok_or("Invalid zkproof")?;

        let typed_issuer = issuer
            .into_encryption_key()
            .ok_or("Invalid issuer")?;

        let typed_total = total
            .into_ciphertext()
            .ok_or("Invalid total")?;

        let typed_rvk = rvk
            .into_verification_key()
            .ok_or("Invalid rvk")?;

        let typed_fee = fee
            .into_ciphertext()
            .ok_or("Invalid fee")?;

        let typed_balance = balance
            .into_ciphertext()
            .ok_or("Invalid balance")?;

        Ok(TypedParams {
            zkproof: typed_zkproof,
            issuer: typed_issuer,
            total: typed_total,
            rvk: typed_rvk,
            dummy_fee: typed_fee,
            dummy_balance: typed_balance,
        })
    }

    /// Get current epoch of specified asset id based on current block height.
    fn get_current_epoch(asset_id: T::AssetId) -> T::BlockNumber {
        let current_height = <system::Module<T>>::block_number();
        current_height / Self::epoch_length(asset_id)
    }

    // PUBLIC MUTABLES

    pub fn rollover(addr: &PkdAddress, asset_id: T::AssetId) -> result::Result<elgamal::Ciphertext<Bls12>, &'static str> {
        let current_epoch = Self::get_current_epoch(asset_id);
        let addr_id = (asset_id, *addr);
        let zero = elgamal::Ciphertext::zero();

        let last_rollover = match Self::last_rollover(addr_id) {
            Some(l) => l,
            None => T::BlockNumber::zero(),
        };

        let pending_transfer = Self::pending_transfer(addr_id);

        // Get balance with the type
        let typed_balance = match Self::encrypted_balance(addr_id) {
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
            <EncryptedBalance<T>>::mutate(addr_id, |balance| {
                let new_balance = balance.clone().map_or(
                    pending_transfer,
                    |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_pending_transfer)))
                );
                *balance = new_balance
            });

            // Reset pending_transfer.
            <PendingTransfer<T>>::remove(addr_id);

            // Set last rollover to current epoch.
            <LastRollOver<T>>::insert(addr_id, current_epoch);
        }

        let res_balance = match Self::encrypted_balance(addr_id) {
            Some(b) => b.into_ciphertext().ok_or("Invalid balance ciphertext")?,
            None => zero.clone(),
        };

        // return actual typed balance.
        Ok(res_balance)
    }

    // Subtracting transferred amount and fee from encrypted balances.
    pub fn sub_enc_balance(
        address: &PkdAddress,
        asset_id: T::AssetId,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>,
        typed_fee: &elgamal::Ciphertext<Bls12>
    ) {
        let amount_plus_fee = typed_amount.add_no_params(&typed_fee);

        <EncryptedBalance<T>>::mutate((asset_id, *address), |balance| {
            let new_balance = balance.clone().map(
                |_| T::EncryptedBalance::from_ciphertext(&typed_balance.sub_no_params(&amount_plus_fee)));
            *balance = new_balance
        });
    }

    /// Adding transferred amount to pending transfer.
    pub fn add_pending_transfer(
        address: &PkdAddress,
        asset_id: T::AssetId,
        typed_balance: &elgamal::Ciphertext<Bls12>,
        typed_amount: &elgamal::Ciphertext<Bls12>
    ) {
        <PendingTransfer<T>>::mutate((asset_id, *address), |pending_transfer| {
            let new_pending_transfer = pending_transfer.clone().map_or(
                Some(T::EncryptedBalance::from_ciphertext(&typed_amount)),
                |_| Some(T::EncryptedBalance::from_ciphertext(&typed_balance.add_no_params(&typed_amount)))
            );
            *pending_transfer = new_pending_transfer
        });
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
    use zprimitives::{Ciphertext, SigVerificationKey, PreparedVk};
    use keys::{ProofGenerationKey, EncryptionKey};
    use jubjub::{curve::{JubjubBls12, FixedGenerators, fs}};
    use pairing::Field;
    use hex_literal::{hex, hex_impl};
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use rand::{SeedableRng, XorShiftRng};
    use test_pairing::{bls12_381::Bls12 as tBls12, Field as tField};
    use test_proofs::{EncryptionKey as tEncryptionKey, SpendingKey as tSpendingKey, elgamal as telgamal, Transaction, PARAMS};
    use zface::transaction::commands::{get_pk, get_vk};
    use scrypto::jubjub::{FixedGenerators as tFixedGenerators, fs::Fs as tFs};


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
        type EncryptedBalance = Ciphertext;
    }

    impl Trait for Test {
        type Event = ();
        type AssetId = u64;
    }

    type EncryptedAssets = Module<Test>;
    type EncryptedBalances = encrypted_balances::Module<Test>;
    type System = system::Module<Test>;

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

    pub fn get_pvk() -> PreparedVk {
        let vk_path = Path::new("../../zface/tests/verification.dat");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        PreparedVk::from_slice(&buf_vk[..])
    }

    fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
        let balance_init = alice_balance_init();
        let epoch_init = alice_epoch_init();

        let (mut t, mut c) = system::GenesisConfig::<Test>::default().build_storage().unwrap();
        let _ = encrypted_balances::GenesisConfig::<Test>{
            encrypted_balance: vec![balance_init.clone()],
			last_rollover: vec![epoch_init],
            epoch_length: 1,
            transaction_base_fee: 1,
            verifying_key: get_pvk(),
        }.assimilate_storage(&mut t, &mut c);
        let _ = GenesisConfig::<Test>{
            encrypted_balance: vec![((0, balance_init.0), balance_init.1)],
			last_rollover: vec![((0, epoch_init.0), epoch_init.1)],
            epoch_length: vec![(0, 1)],
            transaction_base_fee: vec![(0, 1)],
            _genesis_phantom_data: Default::default()
        }.assimilate_storage(&mut t, &mut c);

        t.into()
    }

    #[test]
    fn test_issue_from_zface() {
        with_externalities(&mut new_test_ext(), || {
            let seed = b"Alice                           ".to_vec();
            let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
            let p_g = tFixedGenerators::NoteCommitmentRandomness;

            // Get setuped parameters to compute zk proving.
            let proving_key = get_pk("../../zface/tests/proving.dat").unwrap();
            let prepared_vk = get_vk("../../zface/tests/verification.dat").unwrap();

            let spending_key = tSpendingKey::<tBls12>::from_seed(&seed);
            let enc_key = tEncryptionKey::from_seed(&seed[..], &*PARAMS).unwrap();

            let amount = 100;
            let enc_balance = telgamal::Ciphertext::encrypt(
                amount,
                tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            );

            let tx = Transaction::gen_tx(
                amount,
                0, // dummy value for remaining balance
                &proving_key,
                &prepared_vk,
                &enc_key,
                &spending_key,
                enc_balance,
                rng,
                0
                )
            .expect("fails to generate the tx");

            System::set_block_number(10);

            assert_ok!(EncryptedAssets::issue(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                Proof::from_slice(&tx.proof[..]),
                PkdAddress::from_slice(&tx.address_recipient[..]),
                Ciphertext::from_slice(&tx.enc_amount_recipient[..]),
                Ciphertext::from_slice(&tx.enc_fee[..]),
                Ciphertext::from_slice(&tx.enc_balance[..])
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

            // Get setuped parameters to compute zk proving.
            let proving_key = get_pk("../../zface/tests/proving.dat").unwrap();
            let prepared_vk = get_vk("../../zface/tests/verification.dat").unwrap();

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
                tFs::one(),
                &enc_key,
                p_g,
                &*PARAMS
            );

            let tx = Transaction::gen_tx(
                amount,
                remaining_balance,
                &proving_key,
                &prepared_vk,
                &recipient_account_id,
                &spending_key,
                enc_alice_bal,
                rng,
                fee
                )
            .expect("fails to generate the tx");

            assert_ok!(EncryptedAssets::confidential_transfer(
                Origin::signed(SigVerificationKey::from_slice(&tx.rvk[..])),
                0,
                Proof::from_slice(&tx.proof[..]),
                PkdAddress::from_slice(&tx.address_sender[..]),
                PkdAddress::from_slice(&tx.address_recipient[..]),
                Ciphertext::from_slice(&tx.enc_amount_sender[..]),
                Ciphertext::from_slice(&tx.enc_amount_recipient[..]),
                Ciphertext::from_slice(&tx.enc_fee[..]),
            ));
        })
    }
}
