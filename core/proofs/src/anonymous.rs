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
use zerochain_runtime::{UncheckedExtrinsic, Call, AnonymousBalancesCall};
use zprimitives::{
    EncKey as zEncKey,
    Ciphertext as zCiphertext,
    LeftCiphertext as zLeftCiphertext,
    RightCiphertext as zRightCiphertext,
    Nonce as zNonce,
    Proof as zProof
};
use crate::{
    circuit::AnonymousTransfer,
    elgamal::Ciphertext,
    EncryptionKey,
    ProofGenerationKey,
    SpendingKey,
    KeyContext,
    ProofBuilder,
    constants::*,
};
use crate::crypto_components::{
    MultiEncKeys,
    MultiCiphertexts,
    Anonymous,
    CiphertextTrait,
    Submitter,
    Calls,
    Unchecked,Checked,
    ProofContext, convert_to_checked,
};
use std::{
    io::{self, Write, BufWriter},
    path::Path,
    fs::File,
    marker::PhantomData,
};

impl<E: JubjubEngine> ProofBuilder<E, Anonymous> for KeyContext<E, Anonymous> {
    type Submitter = AnonymousXt;

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
        _fee: u32,
        remaining_balance: u32,
        s_index: usize,
        t_index: usize,
        spending_key: &SpendingKey<E>,
        enc_keys: MultiEncKeys<E, Anonymous>,
        enc_balances: &[Ciphertext<E>],
        g_epoch: edwards::Point<E, PrimeOrder>,
        rng: &mut R,
        params: &E::Params,
    ) -> Result<Self::Submitter, SynthesisError> {
        assert_eq!(enc_balances.len(), ANONIMITY_SIZE);
        let randomness = E::Fs::rand(rng);
        let alpha = E::Fs::rand(rng);

        let pgk = ProofGenerationKey::<E>::from_spending_key(&spending_key, params);
        let dec_key = pgk.into_decryption_key()?;
        let enc_key_sender = pgk.into_encryption_key(params)?;

        let rvk = PublicKey(pgk.0.clone().into())
            .randomize(
                alpha,
                FixedGenerators::NoteCommitmentRandomness,
                params,
        );
        let nonce = g_epoch.mul(dec_key.0, params);

        let instance = AnonymousTransfer {
            params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            s_index: Some(s_index),
            t_index: Some(t_index),
            randomness: Some(&randomness),
            alpha: Some(&alpha),
            proof_generation_key: Some(&pgk),
            dec_key: Some(&dec_key),
            enc_key_recipient: Some(&enc_keys.get_recipient()),
            enc_key_decoys: Some(&enc_keys.get_decoys()),
            enc_balances: Some(&enc_balances),
            g_epoch: Some(&g_epoch),
        };

        // Crate proof
        let proof = create_random_proof(instance, &self.proving_key, rng)?;
        let multi_ciphertexts = MultiCiphertexts::<E, Anonymous>::encrypt(
            amount, 0, &enc_key_sender, &enc_keys, &randomness, params
        );

        ProofContext::new(
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            enc_balances,
            g_epoch,
            nonce
        )
        .check_proof(&self.prepared_vk)?
        .gen_xt(&spending_key, alpha, s_index, t_index)
        .map_err(|e| SynthesisError::IoError(e))
    }
}

impl<E: JubjubEngine> ProofContext<E, Unchecked, Anonymous> {
    fn new(
        proof: Proof<E>,
        rvk: PublicKey<E>,
        enc_key_sender: EncryptionKey<E>,
        enc_keys: MultiEncKeys<E, Anonymous>,
        multi_ciphertexts: MultiCiphertexts<E, Anonymous>,
        enc_balances: &[Ciphertext<E>],
        g_epoch: edwards::Point<E, PrimeOrder>,
        nonce: edwards::Point<E, PrimeOrder>,
    ) -> Self {
        ProofContext {
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            enc_balances: enc_balances.to_vec(),
            g_epoch,
            nonce,
            _marker: PhantomData,
        }
    }

    fn check_proof(
        self,
        prepared_vk: &PreparedVerifyingKey<E>
    ) -> Result<ProofContext<E, Checked, Anonymous>, SynthesisError> {
        Ok(convert_to_checked::<E, Unchecked, Checked, Anonymous>(self))
    }
}

impl<E: JubjubEngine> ProofContext<E, Checked, Anonymous> {
    fn gen_xt(
        &self,
        spending_key: &SpendingKey<E>,
        alpha: E::Fs,
        s_index: usize,
        t_index: usize
    ) -> io::Result<AnonymousXt>
    {
        // Generate the re-randomized sign key
		let mut rsk = [0u8; POINT_SIZE];
		spending_key
            .into_rsk(alpha)
            .write(&mut rsk[..])?;

		let mut rvk = [0u8; POINT_SIZE];
		self
			.rvk
			.write(&mut rvk[..])?;

		let mut proof = [0u8; PROOF_SIZE];
		self
			.proof
			.write(&mut proof[..])?;

        let mut enc_keys = [[0u8; POINT_SIZE]; ANONIMITY_SIZE];
        let mut j = 0;
        for i in 0..ANONIMITY_SIZE {
            let mut e = [0u8; POINT_SIZE];
            if i == s_index {
                self.enc_key_sender.write(&mut e[..])?;
            } else if i == t_index {
                self.enc_key_recipient().write(&mut e[..])?;
            } else {
                self.enc_keys_decoy(j).write(&mut e[..])?;
                j += 1;
            }
            enc_keys[i] = e;
        }

        let mut left_ciphertexts = [[0u8; POINT_SIZE]; ANONIMITY_SIZE];
        let mut j = 0;
        for i in 0..ANONIMITY_SIZE {
            let mut c = [0u8; POINT_SIZE];
            if i == s_index {
                self.left_amount_sender().write(&mut c[..])?;
            } else if i == t_index {
                self.left_amount_recipient().write(&mut c[..])?;
            } else {
                self.left_ciphertext_decoy(j).write(&mut c[..])?;
                j += 1;
            }
            left_ciphertexts[i] = c;
        }

        let mut right_ciphertext = [0u8; POINT_SIZE];
        self.right_randomness()
            .write(&mut right_ciphertext[..])?;

        let mut nonce = [0u8; POINT_SIZE];
		self
			.nonce
			.write(&mut nonce[..])?;

        Ok(AnonymousXt {
            proof,
            enc_keys,
            left_ciphertexts,
            right_ciphertext,
            nonce,
            rsk,
            rvk,
        })
    }

    fn enc_keys_decoy(&self, index: usize) -> &EncryptionKey<E> {
        &self.enc_keys.get_decoys()[index]
    }

    fn left_ciphertext_decoy(&self, index: usize) -> edwards::Point<E, PrimeOrder> {
        self.multi_ciphertexts.get_decoys_left()[index].clone()
    }
}

pub struct AnonymousXt {
    pub proof: [u8; PROOF_SIZE],
    pub enc_keys: [[u8; POINT_SIZE]; ANONIMITY_SIZE],
    pub left_ciphertexts: [[u8; POINT_SIZE]; ANONIMITY_SIZE],
    pub right_ciphertext: [u8; POINT_SIZE],
    pub nonce: [u8; POINT_SIZE],
    pub rsk: [u8; POINT_SIZE],
	pub rvk: [u8; POINT_SIZE],
}

impl Submitter for AnonymousXt {
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
            Calls::AnonymousTransfer => (Compact(index), self.call_transfer(), era, checkpoint),
            _ => unreachable!(),
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

impl AnonymousXt {
    pub fn call_transfer(&self) -> Call {
        let enc_keys = self.enc_keys.iter().map(|e| zEncKey::from_slice(e)).collect();
        let left_ciphertexts = self.left_ciphertexts.iter().map(|e| zLeftCiphertext::from_slice(e)).collect();
        Call::AnonymousBalances(AnonymousBalancesCall::anonymous_transfer(
            zProof::from_slice(&self.proof[..]),
            enc_keys,
            left_ciphertexts,
            zRightCiphertext::from_slice(&self.right_ciphertext[..]),
            zNonce::from_slice(&self.nonce[..])
        ))
    }
}
