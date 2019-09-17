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
    PublicInputBuilder,
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
        let mut enc_keys_vec = enc_keys.get_decoys().to_vec();
        enc_keys_vec.insert(s_index, enc_key_sender.clone());
        enc_keys_vec.insert(t_index, enc_keys.get_recipient().clone());

        let rvk = PublicKey(pgk.0.clone().into())
            .randomize(
                alpha,
                FixedGenerators::NoteCommitmentRandomness,
                params,
        );
        let nonce = g_epoch.mul(dec_key.0, params);

        let multi_ciphertexts = MultiCiphertexts::<E, Anonymous>::encrypt(
            amount, 0, &enc_key_sender, &enc_keys, &randomness, params
        );
        let mut left_ciphertexts = multi_ciphertexts.get_decoys_left();
        left_ciphertexts.insert(s_index, multi_ciphertexts.get_sender().left.clone());
        left_ciphertexts.insert(t_index, multi_ciphertexts.get_recipient().left.clone());

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
            enc_keys: Some(&enc_keys_vec[..]),
            left_ciphertexts: Some(&left_ciphertexts[..]),
            right_ciphertext: Some(multi_ciphertexts.get_right()),
            enc_balances: Some(&enc_balances),
            g_epoch: Some(&g_epoch),
        };

        // Crate proof
        let proof = create_random_proof(instance, &self.proving_key, rng)?;

        ProofContext::new(
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            enc_balances,
            g_epoch,
            nonce,
            s_index,
            t_index,
        )
        .check_proof(&self.prepared_vk)?
        .gen_xt(&spending_key, alpha)
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
        s_index: usize,
        t_index: usize,
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
            s_index: Some(s_index),
            t_index: Some(t_index),
            _marker: PhantomData,
        }
    }

    fn check_proof(
        self,
        prepared_vk: &PreparedVerifyingKey<E>,
    ) -> Result<ProofContext<E, Checked, Anonymous>, SynthesisError> {

        let mut public_inputs = PublicInputBuilder::new(ANONIMOUS_INPUT_SIZE);
        let mut j = 0;
        for i in 0..ANONIMITY_SIZE {
            if Some(i) == self.s_index {
                public_inputs.push(&self.enc_key_sender.0);
            } else if Some(i) == self.t_index {
                public_inputs.push(&self.enc_key_recipient().0);
            } else {
                public_inputs.push(&self.enc_keys_decoy(j).0);
                j += 1;
            }
        }
        let mut j = 0;
        for i in 0..ANONIMITY_SIZE {
            if Some(i) == self.s_index {
                public_inputs.push(self.left_amount_sender());
            } else if Some(i) == self.t_index {
                public_inputs.push(self.left_amount_recipient());
            } else {
                public_inputs.push(&self.left_ciphertext_decoy(j));
                j += 1;
            }
        }
        for lc in self.enc_balances.iter().map(|c| c.left.clone()) {
            public_inputs.push(&lc);
        }
        for rc in self.enc_balances.iter().map(|c| c.right.clone()) {
            public_inputs.push(&rc);
        }
        public_inputs.push(self.right_randomness());
        public_inputs.unknown_push(&self.rvk.0);
        public_inputs.push(&self.g_epoch);
        public_inputs.push(&self.nonce);

        use pairing::{PrimeField, PrimeFieldRepr};
        let mut buf = vec![];
        for r in public_inputs.as_slice() {
            r.into_repr().write_le(&mut &mut buf).map_err(|_| "write error").unwrap();
        }

        match verify_proof(prepared_vk, &self.proof, public_inputs.as_slice()) {
            Ok(e) if !e => return Err(SynthesisError::Unsatisfiable),
            Err(e) => return Err(e),
            _ => { },
        }

        Ok(convert_to_checked::<E, Unchecked, Checked, Anonymous>(self))
    }
}

impl<E: JubjubEngine, C> ProofContext<E, C, Anonymous> {
    fn enc_keys_decoy(&self, index: usize) -> &EncryptionKey<E> {
        &self.enc_keys.get_decoys()[index]
    }

    fn left_ciphertext_decoy(&self, index: usize) -> edwards::Point<E, PrimeOrder> {
        self.multi_ciphertexts.get_decoys_left()[index].clone()
    }
}

impl<E: JubjubEngine> ProofContext<E, Checked, Anonymous> {
    fn gen_xt(
        &self,
        spending_key: &SpendingKey<E>,
        alpha: E::Fs,
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
            if Some(i) == self.s_index {
                self.enc_key_sender.write(&mut e[..])?;
            } else if Some(i) == self.t_index {
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
            if Some(i) == self.s_index {
                self.left_amount_sender().write(&mut c[..])?;
            } else if Some(i) == self.t_index {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rng};
    use scrypto::jubjub::{JubjubBls12, fs::Fs};
    use pairing::{Field, bls12_381::Bls12};

    #[test]
    fn test_gen_anonymous_proof() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let amount = 10;
        let remaining_balance = 90;
        let current_balance = 100;

        let s_index = 0;
        let t_index = 1;

        let sender_seed: [u8; 32] = rng.gen();
        let recipient_seed: [u8; 32] = rng.gen();

        let spending_key = SpendingKey::<Bls12>::from_seed(&sender_seed);
        let enc_key_sender = EncryptionKey::<Bls12>::from_seed(&sender_seed, params).unwrap();
        let enc_key_recipient = EncryptionKey::<Bls12>::from_seed(&recipient_seed, params).unwrap();

        let mut decoys = vec![];
        for _ in 0..10 {
            let random_seed: [u8; 32] = rng.gen();
            let enc_key = EncryptionKey::<Bls12>::from_seed(&random_seed, params)
                .expect("should be generated encryption key from seed.");
            decoys.push(enc_key);
        }

        let mut enc_keys = decoys.clone();
        enc_keys.insert(s_index, enc_key_sender);
        enc_keys.insert(t_index, enc_key_recipient.clone());

        let mut enc_balances = vec![];
        for e in enc_keys.iter() {
            let ciphertext = Ciphertext::encrypt(current_balance, &Fs::one(), &e, p_g, params);
            enc_balances.push(ciphertext);
        }

        let g_epoch = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proofs = KeyContext::read_from_path("../../zface/params/test_anony_pk.dat", "../../zface/params/test_anony_vk.dat")
            .unwrap()
            .gen_proof(
                amount, 0, remaining_balance, s_index, t_index, &spending_key,
                MultiEncKeys::<Bls12, Anonymous>::new(enc_key_recipient, decoys),
                &enc_balances, g_epoch,
                rng, params
            );

        assert!(proofs.is_ok());
    }
}
