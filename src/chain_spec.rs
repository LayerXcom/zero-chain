use primitives::{ed25519, sr25519, Pair, crypto::Ss58Codec};
use zerochain_runtime::{
	AccountId, GenesisConfig, ConsensusConfig, TimestampConfig, BalancesConfig, SudoConfig,
	IndicesConfig, EncryptedBalancesConfig, EncryptedAssetsConfig, ZkSystemConfig,
};
use ed25519::Public as AuthorityId;
use zprimitives::{EncKey, Ciphertext, SigVerificationKey};
use bellman_verifier::PreparedVerifyingKey;
use keys::EncryptionKey;
use zjubjub::{curve::{FixedGenerators, fs}};
use zpairing::{bls12_381::Bls12, Field};
use zcrypto::elgamal;
use zprimitives::PARAMS;
use std::{
	path::Path,
	fs::File,
	io::{BufReader, Read},
	convert::TryFrom,
};

// Note this is the URL for the telemetry server
//const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = substrate_service::ChainSpec<GenesisConfig>;

/// The chain specification option. This is expected to come in from the CLI and
/// is little more than one of a number of alternatives which can easily be converted
/// from a string (`--chain=...`) into a `ChainSpec`.
#[derive(Clone, Debug)]
pub enum Alternative {
	/// Whatever the current runtime is, with just Alice as an auth.
	Development,
	/// Whatever the current runtime is, with simple Alice/Bob auths.
	LocalTestnet,
}

fn authority_key(s: &str) -> AuthorityId {
	ed25519::Pair::from_string(&format!("//{}", s), None)
		.expect("static values are valid; qed")
		.public()
}

// fn account_key(s: &str) -> AccountId {
// 	sr25519::Pair::from_string(&format!("//{}", s), None)
// 		.expect("static values are valid; qed")
// 		.public()
// }

impl Alternative {
	/// Get an actual chain config from one of the alternatives.
	pub(crate) fn load(self) -> Result<ChainSpec, String> {
		Ok(match self {
			Alternative::Development => ChainSpec::from_genesis(
				"Development",
				"dev",
				|| testnet_genesis(vec![
					authority_key("Alice")
				], vec![
					SigVerificationKey::from_slice(b"Alice                           ")
				],
					SigVerificationKey::from_slice(b"Alice                           ")
				),
				vec![],
				None,
				None,
				None,
				None
			),
			Alternative::LocalTestnet => ChainSpec::from_genesis(
				"Local Testnet",
				"local_testnet",
				|| testnet_genesis(vec![
					authority_key("Alice"),
					authority_key("Bob"),
					authority_key("Charlie")
				], vec![
					SigVerificationKey::from_slice(b"Alice                           ")
					// account_key("Bob"),
					// account_key("Charlie"),
					// account_key("Dave"),
					// account_key("Eve"),
					// account_key("Ferdie"),
				],
					SigVerificationKey::from_slice(b"Alice                           ")
				),
				vec![],
				None,
				None,
				None,
				None
			),
		})
	}

	pub(crate) fn from(s: &str) -> Option<Self> {
		match s {
			"dev" => Some(Alternative::Development),
			"" | "local" => Some(Alternative::LocalTestnet),
			_ => None,
		}
	}
}

fn testnet_genesis(initial_authorities: Vec<AuthorityId>, endowed_accounts: Vec<AccountId>, root_key: AccountId) -> GenesisConfig {
	let balance_init = alice_balance_init();
	let epoch_init = alice_epoch_init();
	GenesisConfig {
		consensus: Some(ConsensusConfig {
			code: include_bytes!("../runtime/wasm/target/wasm32-unknown-unknown/release/zerochain_runtime_wasm.compact.wasm").to_vec(),
			authorities: initial_authorities.clone(),
		}),
		system: None,
		timestamp: Some(TimestampConfig {
			minimum_period: 10,	// 10 second block time.
		}),
		indices: Some(IndicesConfig {
			ids: endowed_accounts.clone(),
		}),
		balances: Some(BalancesConfig {
			transaction_base_fee: 1,
			transaction_byte_fee: 0,
			existential_deposit: 500,
			transfer_fee: 0,
			creation_fee: 0,
			balances: endowed_accounts.iter().cloned().map(|k|(k, 1 << 60)).collect(),
			vesting: vec![],
		}),
		sudo: Some(SudoConfig {
			key: root_key,
		}),
		encrypted_balances: Some(EncryptedBalancesConfig {
			encrypted_balance: vec![balance_init.clone()],
			last_rollover: vec![epoch_init],
			transaction_base_fee: 1,
			_genesis_phantom_data: Default::default(),
		}),
		encrypted_assets: Some(EncryptedAssetsConfig {
			encrypted_balance: vec![((0, balance_init.0), balance_init.1)],
			last_rollover: vec![((0, epoch_init.0), epoch_init.1)],
			_genesis_phantom_data: Default::default(),
		}),
		zk_system: Some(ZkSystemConfig {
			last_epoch: 0,
			epoch_length: 3,
			nonce_pool: vec![],
			confidential_vk: get_conf_vk(),
			anonymous_vk: get_anony_vk()
		})
	}
}

fn get_conf_vk() -> PreparedVerifyingKey<Bls12> {
	let vk_path = Path::new("./zface/params/conf_vk.dat");
	let vk_file = File::open(&vk_path).unwrap();
	let mut vk_reader = BufReader::new(vk_file);

	let mut buf_vk = vec![];
    vk_reader.read_to_end(&mut buf_vk).unwrap();

	PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap()
}

fn get_anony_vk() -> PreparedVerifyingKey<Bls12> {
	let vk_path = Path::new("./zface/params/anony_vk.dat");
	let vk_file = File::open(&vk_path).unwrap();
	let mut vk_reader = BufReader::new(vk_file);

	let mut buf_vk = vec![];
    vk_reader.read_to_end(&mut buf_vk).unwrap();

	PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap()
}

fn alice_balance_init() -> (EncKey, Ciphertext) {
	let enc_key = get_alice_enc_key();
	let alice_value = 10_000 as u32;
	let p_g = FixedGenerators::Diversifier; // 1 same as NoteCommitmentRandomness;

	// The default balance is not encrypted with randomness.
	let enc_alice_bal = elgamal::Ciphertext::encrypt(alice_value, &fs::Fs::one(), &enc_key, p_g, &PARAMS);

	(EncKey::try_from(enc_key).unwrap(), Ciphertext::try_from(enc_alice_bal).unwrap())
}

fn alice_epoch_init() -> (EncKey, u64) {
	let enc_key = get_alice_enc_key();

	(EncKey::try_from(enc_key).unwrap(), 0)
}

fn get_alice_enc_key() -> EncryptionKey<Bls12> {
	// use zface::ss58::EncryptionKeyBytes;
	// let ss58_address = "5DC4kJ84b4KfVyddcFMYfy5skTJWVtxtWRETZo2i4nh8Ao1i";
	// let enc_key_bytes = EncryptionKeyBytes::from_ss58check(ss58_address).unwrap();
	// let enc_key = EncryptionKey::read(&mut &enc_key_bytes.0[..], &*PARAMS).unwrap();
	let alice_seed = b"Alice                           ".to_vec();
	let enc_key = EncryptionKey::<Bls12>::from_seed(&&alice_seed, &*PARAMS)
		.expect("should be generated encryption key from seed.");
	enc_key
}
