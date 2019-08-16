use bellman::{
        groth16::{
            create_random_proof,
            verify_proof,
            Parameters,
            PreparedVerifyingKey,
            Proof,
        },
        SynthesisError,
};
use pairing::Field;
use rand::{Rand, Rng};
use scrypto::{
    jubjub::{
        JubjubEngine,
        FixedGenerators,
        edwards,
        PrimeOrder,
    },
    redjubjub::PublicKey,
};
use polkadot_rs::Api;
use zerochain_runtime::{UncheckedExtrinsic, Call, EncryptedBalancesCall, EncryptedAssetsCall};
use zprimitives::{
    EncKey as zEncKey,
    Ciphertext as zCiphertext,
    LeftCiphertext as zLeftCiphertext,
    RightCiphertext as zRightCiphertext,
    Nonce as zNonce,
    Proof as zProof
};
use crate::circuit::Transfer;
use crate::elgamal::Ciphertext;
use crate::{
    EncryptionKey,
    ProofGenerationKey,
    SpendingKey,
};
use crate::crypto_components::{
    MultiEncKeys,
    MultiCiphertexts,
    Confidential,
    CiphertextTrait,
    PrivacyConfing
};
use std::{
    io::{self, Write, BufReader, BufWriter, Read},
    path::Path,
    fs::File,
    marker::PhantomData,
};

pub trait ProofBuilder<E: JubjubEngine>: Sized {
    type Submitter: Submitter;
    type PC: PrivacyConfing;

    fn setup<R: Rng>(rng: &mut R) -> Self;

    fn write_to_file<P: AsRef<Path>>(&self, pk_path: P, vk_path: P) -> io::Result<()>;

    fn read_from_path<P: AsRef<Path>>(pk_path: P, vk_path: P) -> io::Result<Self>;

    fn gen_proof<R: Rng>(
        &self,
        amount: u32,
        fee: u32,
        remaining_balance: u32,
        spending_key: &SpendingKey<E>,
        enc_keys: MultiEncKeys<E, Self::PC>,
        encrypted_balance: &Ciphertext<E>,
        g_epoch: edwards::Point<E, PrimeOrder>,
        rng: &mut R,
        params: &E::Params,
    ) -> Result<Self::Submitter, SynthesisError>;
}

pub struct KeyContext<E: JubjubEngine> {
    proving_key: Parameters<E>,
    prepared_vk: PreparedVerifyingKey<E>,
}

impl<E: JubjubEngine> KeyContext<E> {
    pub fn new(proving_key: Parameters<E>, prepared_vk: PreparedVerifyingKey<E>) -> Self {
        KeyContext {
            proving_key,
            prepared_vk,
        }
    }

    pub fn pk(&self) -> &Parameters<E> {
        &self.proving_key
    }

    pub fn vk(&self) -> &PreparedVerifyingKey<E> {
        &self.prepared_vk
    }

    fn inner_read<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
        let file = File::open(&path)?;

        let mut reader = BufReader::new(file);
        let mut buffer = vec![];
        reader.read_to_end(&mut buffer)?;

        Ok(buffer)
    }
}

impl<E: JubjubEngine> ProofBuilder<E> for KeyContext<E> {
    type Submitter = ConfidentialXt;
    type PC = Confidential;

    // TODO:
    fn setup<R: Rng>(_rng: &mut R) -> Self {
        unimplemented!();
    }

    fn write_to_file<P: AsRef<Path>>(&self, pk_path: P, vk_path: P) -> io::Result<()> {
        let pk_file = File::create(&pk_path)?;
        let vk_file = File::create(&vk_path)?;

        let mut bw_pk = BufWriter::new(pk_file);
        let mut bw_vk = BufWriter::new(vk_file);

        let mut v_pk = vec![];
        let mut v_vk = vec![];

        self.proving_key.write(&mut &mut v_pk)?;
        self.prepared_vk.write(&mut &mut v_vk)?;

        bw_pk.write(&v_pk[..])?;
        bw_vk.write(&v_vk[..])?;

        bw_pk.flush()?;
        bw_vk.flush()?;

        Ok(())
    }

    fn read_from_path<P: AsRef<Path>>(pk_path: P, vk_path: P) -> io::Result<Self>{
        let pk_buf = Self::inner_read(pk_path)?;
        let vk_buf = Self::inner_read(vk_path)?;

        let pk = Parameters::read(&pk_buf[..], true)?;
        let vk = PreparedVerifyingKey::read(&vk_buf[..])?;

        Ok(KeyContext::new(pk, vk))
    }

    fn gen_proof<R: Rng>(
        &self,
        amount: u32,
        fee: u32,
        remaining_balance: u32,
        spending_key: &SpendingKey<E>,
        enc_keys: MultiEncKeys<E, Self::PC>,
        encrypted_balance: &Ciphertext<E>,
        g_epoch: edwards::Point<E, PrimeOrder>,
        rng: &mut R,
        params: &E::Params,
    ) -> Result<Self::Submitter, SynthesisError> {
        let randomness = E::Fs::rand(rng);
        let alpha = E::Fs::rand(rng);

        let proof_generation_key = ProofGenerationKey::<E>::from_spending_key(&spending_key, params);
        let dec_key_sender = proof_generation_key.into_decryption_key()?;
        let enc_key_sender = proof_generation_key.into_encryption_key(params)?;

        let rvk = PublicKey(proof_generation_key.0.clone().into())
            .randomize(
                alpha,
                FixedGenerators::NoteCommitmentRandomness,
                params,
        );
        let nonce = g_epoch.mul(dec_key_sender.0, params);

        let instance = Transfer {
            params: params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            randomness: Some(&randomness),
            alpha: Some(&alpha),
            proof_generation_key: Some(&proof_generation_key),
            dec_key_sender: Some(&dec_key_sender),
            enc_key_recipient: Some(&enc_keys.get_recipient()),
            encrypted_balance: Some(&encrypted_balance),
            fee: Some(fee),
            g_epoch: Some(&g_epoch),
        };

        // Crate proof
        let proof = create_random_proof(instance, &self.proving_key, rng)?;
        let multi_ciphertexts = MultiCiphertexts::<E, Confidential>::encrypt(
            amount,
            fee,
            &enc_key_sender,
            &enc_keys,
            &randomness,
            params
        );

        ConfidentialProofContext::new(
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            encrypted_balance.clone(), // TODO
            g_epoch,
            nonce
        )
        .check_proof(&self.prepared_vk)?
        .gen_xt(&spending_key, alpha)
        .map_err(|e| SynthesisError::IoError(e))
    }
}

struct Unchecked;
struct Checked;
trait ProofChecking { }

impl ProofChecking for Unchecked { }
impl ProofChecking for Checked { }

#[derive(Clone)]
struct ConfidentialProofContext<E: JubjubEngine, IsChecked, PC: PrivacyConfing> {
    proof: Proof<E>,
    rvk: PublicKey<E>, // re-randomization sig-verifying key
    enc_key_sender: EncryptionKey<E>,
    enc_keys: MultiEncKeys<E, PC>,
    multi_ciphertexts: MultiCiphertexts<E, PC>,
    encrypted_balance: Ciphertext<E>,
    g_epoch: edwards::Point<E, PrimeOrder>,
    nonce: edwards::Point<E, PrimeOrder>,
    _marker: PhantomData<IsChecked>,
}

impl<E: JubjubEngine, IsChecked, PC: PrivacyConfing> ConfidentialProofContext<E, IsChecked, PC> {
    fn left_amount_sender(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_sender().left
    }

    fn left_amount_recipient(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_recipient().left
    }

    fn left_fee(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_fee().left
    }

    fn right_randomness(&self) -> &edwards::Point<E, PrimeOrder> {
        let sender_right = &self.multi_ciphertexts.get_sender().right;
        let recipient_right = &self.multi_ciphertexts.get_recipient().right;
        let fee_right = &self.multi_ciphertexts.get_fee().right;

        assert!(sender_right == recipient_right);
        assert!(recipient_right == fee_right);

        &sender_right
    }

    fn recipient(&self) -> &EncryptionKey<E> {
        self.enc_keys.get_recipient()
    }
}

impl<E: JubjubEngine, PC: PrivacyConfing> ConfidentialProofContext<E, Unchecked, PC> {
    fn new(
        proof: Proof<E>,
        rvk: PublicKey<E>,
        enc_key_sender: EncryptionKey<E>,
        enc_keys: MultiEncKeys<E, PC>,
        multi_ciphertexts: MultiCiphertexts<E, PC>,
        encrypted_balance: Ciphertext<E>,
        g_epoch: edwards::Point<E, PrimeOrder>,
        nonce: edwards::Point<E, PrimeOrder>,
    ) -> Self {
        ConfidentialProofContext {
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            encrypted_balance,
            g_epoch,
            nonce,
            _marker: PhantomData,
        }
    }

    fn check_proof(
        self,
        prepared_vk: &PreparedVerifyingKey<E>
    ) -> Result<ConfidentialProofContext<E, Checked, PC>, SynthesisError> {
        let mut public_input = [E::Fr::zero(); 22];

        {
            let (x, y) = self.enc_key_sender.0.into_xy();
            public_input[0] = x;
            public_input[1] = y;
        }
        {
            let (x, y) = self.enc_keys.get_recipient().0.into_xy();
            public_input[2] = x;
            public_input[3] = y;
        }
        {
            let (x, y) = self.left_amount_sender().into_xy();
            public_input[4] = x;
            public_input[5] = y;
        }
        {
            let (x, y) = self.left_amount_recipient().into_xy();
            public_input[6] = x;
            public_input[7] = y;
        }
        {
            let (x, y) = self.right_randomness().into_xy();
            public_input[8] = x;
            public_input[9] = y;
        }
        {
            let (x, y) = self.left_fee().into_xy();
            public_input[10] = x;
            public_input[11] = y;
        }
        {
            let (x, y) = self.encrypted_balance.left.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = self.encrypted_balance.right.into_xy();
            public_input[14] = x;
            public_input[15] = y;
        }
        {
            let (x, y) = self.rvk.0.into_xy();
            public_input[16] = x;
            public_input[17] = y;
        }
        {
            let (x, y) = self.g_epoch.into_xy();
            public_input[18] = x;
            public_input[19] = y;
        }
        {
            let (x, y) = self.nonce.into_xy();
            public_input[20] = x;
            public_input[21] = y;
        }

        // This verification is just an error handling, not validate if it returns `true`,
        // because public input of encrypted balance needs to be updated on-chain.
        if let Err(_) = verify_proof(prepared_vk, &self.proof, &public_input[..]) {
            return Err(SynthesisError::MalformedVerifyingKey)
        }

        Ok(convert_to_checked::<E, Unchecked, Checked, PC>(self))
    }
}

fn convert_to_checked<E: JubjubEngine, C1, C2, PC: PrivacyConfing>(from: ConfidentialProofContext<E, C1, PC>) -> ConfidentialProofContext<E, C2, PC> {
    ConfidentialProofContext {
        proof: from.proof,
        rvk: from.rvk,
        enc_key_sender: from.enc_key_sender,
        enc_keys: from.enc_keys,
        multi_ciphertexts: from.multi_ciphertexts,
        encrypted_balance: from.encrypted_balance,
        g_epoch: from.g_epoch,
        nonce: from.nonce,
        _marker: PhantomData,
    }
}

impl<E: JubjubEngine, PC: PrivacyConfing> ConfidentialProofContext<E, Checked, PC> {
    fn gen_xt(&self, spending_key: &SpendingKey<E>, alpha: E::Fs) -> io::Result<ConfidentialXt> {

        // Generate the re-randomized sign key
		let mut rsk_bytes = [0u8; 32];
		spending_key
            .into_rsk(alpha)
            .write(&mut rsk_bytes[..])?;

		let mut rvk_bytes = [0u8; 32];
		self
			.rvk
			.write(&mut rvk_bytes[..])?;

		let mut proof_bytes = [0u8; 192];
		self
			.proof
			.write(&mut proof_bytes[..])?;

		let mut enc_key_sender = [0u8; 32];
		self
			.enc_key_sender
			.write(&mut enc_key_sender[..])?;

		let mut enc_key_recipient = [0u8; 32];
		self
			.recipient()
			.write(&mut enc_key_recipient[..])?;

        let mut left_amount_sender = [0u8; 32];
		self
			.left_amount_sender()
			.write(&mut left_amount_sender[..])?;

		let mut left_amount_recipient = [0u8; 32];
		self
            .left_amount_recipient()
			.write(&mut left_amount_recipient[..])?;

		let mut left_fee = [0u8; 32];
		self
			.left_fee()
			.write(&mut left_fee[..])?;

        let mut right_randomness = [0u8; 32];
        self
            .right_randomness()
            .write(&mut right_randomness[..])?;

		let mut enc_balance = [0u8; 64];
		self
            .encrypted_balance
			.write(&mut enc_balance[..])?;

		let mut nonce = [0u8; 32];
		self
			.nonce
			.write(&mut nonce[..])?;

		let tx = ConfidentialXt {
			proof: proof_bytes,
			rvk: rvk_bytes,
			enc_key_sender,
			enc_key_recipient,
			left_amount_sender,
			left_amount_recipient,
            left_fee,
            right_randomness,
			rsk: rsk_bytes,
			enc_balance,
			nonce,
		};

		Ok(tx)
    }
}

pub trait Submitter {
    fn submit<R: Rng>(&self, calls: Calls, api: &Api, rng: &mut R);
}

/// Transaction components which is needed to create a signed `UncheckedExtrinsic`.
pub struct ConfidentialXt{
    pub proof: [u8; 192],
    pub enc_key_sender: [u8; 32],
    pub enc_key_recipient: [u8; 32],
    pub left_amount_sender: [u8; 32],
    pub left_amount_recipient: [u8; 32],
	pub left_fee: [u8; 32],
    pub right_randomness: [u8; 32],
	pub rsk: [u8; 32],
	pub rvk: [u8; 32],
	pub enc_balance: [u8; 64],
	pub nonce: [u8; 32],
}

impl Submitter for ConfidentialXt {
    fn submit<R: Rng>(&self, calls: Calls, api: &Api, rng: &mut R) {
        use zjubjub::{
            curve::{fs::Fs as zFs, FixedGenerators as zFixedGenerators},
            redjubjub,
        };
        use zpairing::{
            bls12_381::Bls12 as zBls12,
            PrimeField as zPrimeField,
            PrimeFieldRepr as zPrimeFieldRepr
        };
        use parity_codec::{Compact, Encode};
        use primitives::blake2_256;
        use runtime_primitives::generic::Era;
        use zprimitives::{PARAMS as ZPARAMS, SigVerificationKey, RedjubjubSignature};
        use std::convert::TryFrom;

        let p_g = zFixedGenerators::Diversifier; // 1

        let mut rsk_repr = zFs::default().into_repr();
        rsk_repr.read_le(&mut &self.rsk[..])
            .expect("should be casted to Fs's repr type.");
        let rsk = zFs::from_repr(rsk_repr)
            .expect("should be casted to Fs type from repr type.");

        let sig_sk = redjubjub::PrivateKey::<zBls12>(rsk);
        let sig_vk = SigVerificationKey::from_slice(&self.rvk[..]);

        let era = Era::Immortal;
        let index = api.get_nonce(&sig_vk).expect("Nonce must be got.");
        let checkpoint = api.get_genesis_blockhash()
            .expect("should be fetched the genesis block hash from zerochain node.");

        let raw_payload = match calls {
            Calls::BalanceTransfer => (Compact(index), self.call_transfer(), era, checkpoint),
            Calls::AssetIssue => (Compact(index), self.call_asset_issue(), era, checkpoint),
            Calls::AssetTransfer(asset_id) => (Compact(index), self.call_asset_transfer(asset_id), era, checkpoint),
            Calls::AssetBurn(asset_id) => (Compact(index), self.call_asset_burn(asset_id), era, checkpoint),
        };

        let sig = raw_payload.using_encoded(|payload| {
            let msg = blake2_256(payload);
            let sig = sig_sk.sign(&msg[..], rng, p_g, &*ZPARAMS);

            let sig_vk = redjubjub::PublicKey::<zBls12>::try_from(sig_vk)
                .expect("should be casted to redjubjub::PublicKey<Bls12> type.");
            assert!(sig_vk.verify(&msg, &sig, p_g, &*ZPARAMS));

            sig
        });

        let sig_repr = RedjubjubSignature::try_from(sig)
            .expect("shoukd be casted from RedjubjubSignature.");
        let uxt = UncheckedExtrinsic::new_signed(index, raw_payload.1, sig_vk.into(), sig_repr, era);
        let _tx_hash = api.submit_extrinsic(&uxt)
            .expect("Faild to submit a extrinsic to zerochain node.");
    }
}

pub enum Calls {
    BalanceTransfer,
    AssetIssue,
    AssetTransfer(u32),
    AssetBurn(u32),
}

impl ConfidentialXt {
    pub fn call_transfer(&self) -> Call {
        Call::EncryptedBalances(EncryptedBalancesCall::confidential_transfer(
            zProof::from_slice(&self.proof[..]),
            zEncKey::from_slice(&self.enc_key_sender[..]),
            zEncKey::from_slice(&self.enc_key_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_amount_sender[..]),
            zLeftCiphertext::from_slice(&self.left_amount_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_fee[..]),
            zRightCiphertext::from_slice(&self.right_randomness[..]),
            zNonce::from_slice(&self.nonce[..])
        ))
    }

    pub fn call_asset_issue(&self) -> Call {
        Call::EncryptedAssets(EncryptedAssetsCall::issue(
            zProof::from_slice(&self.proof[..]),
            zEncKey::from_slice(&self.enc_key_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_amount_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_fee[..]),
            zCiphertext::from_slice(&self.enc_balance[..]),
            zRightCiphertext::from_slice(&self.right_randomness[..]),
            zNonce::from_slice(&self.nonce[..])
        ))
    }

    pub fn call_asset_transfer(&self, asset_id: u32) -> Call {
        Call::EncryptedAssets(EncryptedAssetsCall::confidential_transfer(
            asset_id,
            zProof::from_slice(&self.proof[..]),
            zEncKey::from_slice(&self.enc_key_sender[..]),
            zEncKey::from_slice(&self.enc_key_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_amount_sender[..]),
            zLeftCiphertext::from_slice(&self.left_amount_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_fee[..]),
            zRightCiphertext::from_slice(&self.right_randomness[..]),
            zNonce::from_slice(&self.nonce[..])
        ))
    }

    pub fn call_asset_burn(&self, asset_id: u32) -> Call {
        Call::EncryptedAssets(EncryptedAssetsCall::destroy(
            zProof::from_slice(&self.proof[..]),
            zEncKey::from_slice(&self.enc_key_recipient[..]),
            asset_id,
            zLeftCiphertext::from_slice(&self.left_amount_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_fee[..]),
            zCiphertext::from_slice(&self.enc_balance[..]),
            zRightCiphertext::from_slice(&self.right_randomness[..]),
            zNonce::from_slice(&self.nonce[..])
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rng};
    use crate::EncryptionKey;
    use scrypto::jubjub::JubjubBls12;
    use pairing::bls12_381::Bls12;
    use std::path::Path;
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn test_gen_proof() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let amount = 10 as u32;
        let remaining_balance = 89 as u32;
        let balance = 100 as u32;
        let fee = 1 as u32;

        let sender_seed: [u8; 32] = rng.gen();
        let recipient_seed: [u8; 32] = rng.gen();

        let spending_key = SpendingKey::<Bls12>::from_seed(&sender_seed);
        let enc_key_recipient = EncryptionKey::<Bls12>::from_seed(&recipient_seed, params).unwrap();

        let randomness = rng.gen();
        let enc_key = EncryptionKey::from_seed(&sender_seed[..], params).unwrap();
        let encrypted_balance = Ciphertext::encrypt(balance, &randomness, &enc_key, p_g, params);

        let g_epoch = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proofs = KeyContext::read_from_path("../../zface/proving.params", "../../zface/verification.params")
            .unwrap()
            .gen_proof(
                amount, fee, remaining_balance, &spending_key,
                MultiEncKeys::<Bls12, Confidential>::new(enc_key_recipient),
                &encrypted_balance, g_epoch,
                rng, params
            );

        assert!(proofs.is_ok());
    }

    #[test]
    fn test_read_proving_key() {
        let pk_path = Path::new("../../zface/proving.params");

        let pk_file = File::open(&pk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        println!("{:?}", pk_reader);
        let mut buf = vec![];

        pk_reader.read_to_end(&mut buf).unwrap();
        println!("{:?}", buf.len());

        let _proving_key = Parameters::<Bls12>::read(&mut &buf[..], true).unwrap();
    }
}
