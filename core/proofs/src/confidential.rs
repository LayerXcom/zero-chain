use crate::crypto_components::{
    convert_to_checked, Calls, Checked, CiphertextTrait, Confidential, MultiCiphertexts,
    MultiEncKeys, ProofContext, Submitter, Unchecked,
};
use crate::{
    circuit::ConfidentialTransfer, constants::*, elgamal::Ciphertext, EncryptionKey, KeyContext,
    ProofBuilder, ProofGenerationKey, SpendingKey,
};
use bellman::{
    groth16::{create_random_proof, verify_proof, Parameters, PreparedVerifyingKey, Proof},
    SynthesisError,
};
use pairing::Field;
use polkadot_rs::Api;
use rand::{Rand, Rng};
use scrypto::{
    jubjub::{edwards, FixedGenerators, JubjubEngine, PrimeOrder},
    redjubjub::PublicKey,
};
use std::{
    fs::File,
    io::{self, BufWriter, Write},
    marker::PhantomData,
    path::Path,
};
use zerochain_runtime::{
    AnonymousBalancesCall, Call, EncryptedAssetsCall, EncryptedBalancesCall, UncheckedExtrinsic,
};
use zprimitives::{
    Ciphertext as zCiphertext, EncKey as zEncKey, LeftCiphertext as zLeftCiphertext,
    Nonce as zNonce, Proof as zProof, RightCiphertext as zRightCiphertext,
};

impl<E: JubjubEngine> ProofBuilder<E, Confidential> for KeyContext<E, Confidential> {
    type Submitter = ConfidentialXt;

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

    fn read_from_path<P: AsRef<Path>>(pk_path: P, vk_path: P) -> io::Result<Self> {
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
        _s_index: usize,
        _t_index: usize,
        spending_key: &SpendingKey<E>,
        enc_keys: MultiEncKeys<E, Confidential>,
        encrypted_balance: &[Ciphertext<E>],
        g_epoch: edwards::Point<E, PrimeOrder>,
        rng: &mut R,
        params: &E::Params,
    ) -> Result<Self::Submitter, SynthesisError> {
        let randomness = E::Fs::rand(rng);
        let alpha = E::Fs::rand(rng);

        let pgk = ProofGenerationKey::<E>::from_spending_key(&spending_key, params);
        let dec_key = pgk.into_decryption_key()?;
        let enc_key_sender = pgk.into_encryption_key(params)?;

        let rvk = PublicKey(pgk.0.clone().into()).randomize(
            alpha,
            FixedGenerators::NoteCommitmentRandomness,
            params,
        );
        let nonce = g_epoch.mul(dec_key.0, params);

        let instance = ConfidentialTransfer {
            params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            randomness: Some(&randomness),
            alpha: Some(&alpha),
            proof_generation_key: Some(&pgk),
            dec_key_sender: Some(&dec_key),
            enc_key_recipient: Some(&enc_keys.get_recipient()),
            encrypted_balance: Some(&encrypted_balance[0]),
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
            params,
        );

        ProofContext::new(
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            encrypted_balance[0].clone(), // TODO
            g_epoch,
            nonce,
        )
        .check_proof(&self.prepared_vk)?
        .gen_xt(&spending_key, alpha)
        .map_err(|e| SynthesisError::IoError(e))
    }
}

impl<E: JubjubEngine, IsChecked> ProofContext<E, IsChecked, Confidential> {
    fn left_fee(&self) -> &edwards::Point<E, PrimeOrder> {
        &self.multi_ciphertexts.get_fee().left
    }
}

impl<E: JubjubEngine> ProofContext<E, Unchecked, Confidential> {
    fn new(
        proof: Proof<E>,
        rvk: PublicKey<E>,
        enc_key_sender: EncryptionKey<E>,
        enc_keys: MultiEncKeys<E, Confidential>,
        multi_ciphertexts: MultiCiphertexts<E, Confidential>,
        encrypted_balance: Ciphertext<E>,
        g_epoch: edwards::Point<E, PrimeOrder>,
        nonce: edwards::Point<E, PrimeOrder>,
    ) -> Self {
        let enc_balances = vec![encrypted_balance];
        ProofContext {
            proof,
            rvk,
            enc_key_sender,
            enc_keys,
            multi_ciphertexts,
            enc_balances,
            g_epoch,
            nonce,
            s_index: None,
            t_index: None,
            _marker: PhantomData,
        }
    }

    fn check_proof(
        self,
        prepared_vk: &PreparedVerifyingKey<E>,
    ) -> Result<ProofContext<E, Checked, Confidential>, SynthesisError> {
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
        assert_eq!(self.enc_balances.len(), 1);
        {
            let (x, y) = self.enc_balances[0].left.into_xy();
            public_input[12] = x;
            public_input[13] = y;
        }
        {
            let (x, y) = self.enc_balances[0].right.into_xy();
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

        match verify_proof(prepared_vk, &self.proof, &public_input[..]) {
            Ok(e) if !e => return Err(SynthesisError::Unsatisfiable),
            Err(e) => return Err(e),
            _ => {}
        }

        Ok(convert_to_checked::<E, Unchecked, Checked, Confidential>(
            self,
        ))
    }
}

impl<E: JubjubEngine> ProofContext<E, Checked, Confidential> {
    fn gen_xt(&self, spending_key: &SpendingKey<E>, alpha: E::Fs) -> io::Result<ConfidentialXt> {
        // Generate the re-randomized sign key
        let mut rsk_bytes = [0u8; 32];
        spending_key.into_rsk(alpha).write(&mut rsk_bytes[..])?;

        let mut rvk_bytes = [0u8; 32];
        self.rvk.write(&mut rvk_bytes[..])?;

        let mut proof_bytes = [0u8; 192];
        self.proof.write(&mut proof_bytes[..])?;

        let mut enc_key_sender = [0u8; 32];
        self.enc_key_sender.write(&mut enc_key_sender[..])?;

        let mut enc_key_recipient = [0u8; 32];
        self.enc_key_recipient().write(&mut enc_key_recipient[..])?;

        let mut left_amount_sender = [0u8; 32];
        self.left_amount_sender()
            .write(&mut left_amount_sender[..])?;

        let mut left_amount_recipient = [0u8; 32];
        self.left_amount_recipient()
            .write(&mut left_amount_recipient[..])?;

        let mut left_fee = [0u8; 32];
        self.left_fee().write(&mut left_fee[..])?;

        let mut right_randomness = [0u8; 32];
        self.right_randomness().write(&mut right_randomness[..])?;

        let mut enc_balance = [0u8; 64];
        self.enc_balances[0].write(&mut enc_balance[..])?;

        let mut nonce = [0u8; 32];
        self.nonce.write(&mut nonce[..])?;

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

/// Transaction components which is needed to create a signed `UncheckedExtrinsic`.
pub struct ConfidentialXt {
    pub proof: [u8; PROOF_SIZE],
    pub enc_key_sender: [u8; POINT_SIZE],
    pub enc_key_recipient: [u8; POINT_SIZE],
    pub left_amount_sender: [u8; POINT_SIZE],
    pub left_amount_recipient: [u8; POINT_SIZE],
    pub left_fee: [u8; POINT_SIZE],
    pub right_randomness: [u8; POINT_SIZE],
    pub rsk: [u8; POINT_SIZE],
    pub rvk: [u8; POINT_SIZE],
    pub enc_balance: [u8; CIPHERTEXT_SIZE],
    pub nonce: [u8; POINT_SIZE],
}

impl Submitter for ConfidentialXt {
    fn submit<R: Rng>(&self, calls: Calls, api: &Api, rng: &mut R) {
        use parity_codec::{Compact, Encode};
        use primitives::blake2_256;
        use runtime_primitives::generic::Era;
        use std::convert::TryFrom;
        use zjubjub::{
            curve::{fs::Fs as zFs, FixedGenerators as zFixedGenerators},
            redjubjub,
        };
        use zpairing::{
            bls12_381::Bls12 as zBls12, PrimeField as zPrimeField,
            PrimeFieldRepr as zPrimeFieldRepr,
        };
        use zprimitives::{RedjubjubSignature, SigVerificationKey, PARAMS as ZPARAMS};

        let p_g = zFixedGenerators::Diversifier; // 1

        let mut rsk_repr = zFs::default().into_repr();
        rsk_repr
            .read_le(&mut &self.rsk[..])
            .expect("should be casted to Fs's repr type.");
        let rsk = zFs::from_repr(rsk_repr).expect("should be casted to Fs type from repr type.");

        let sig_sk = redjubjub::PrivateKey::<zBls12>(rsk);
        let sig_vk = SigVerificationKey::from_slice(&self.rvk[..]);

        let era = Era::Immortal;
        let index = api.get_nonce(&sig_vk).expect("Nonce must be got.");
        let checkpoint = api
            .get_genesis_blockhash()
            .expect("should be fetched the genesis block hash from zerochain node.");

        let raw_payload = match calls {
            Calls::BalanceTransfer => (Compact(index), self.call_transfer(), era, checkpoint),
            Calls::AssetIssue => (Compact(index), self.call_asset_issue(), era, checkpoint),
            Calls::AssetTransfer(asset_id) => (
                Compact(index),
                self.call_asset_transfer(asset_id),
                era,
                checkpoint,
            ),
            Calls::AssetBurn(asset_id) => (
                Compact(index),
                self.call_asset_burn(asset_id),
                era,
                checkpoint,
            ),
            Calls::AnonymousIssue => (Compact(index), self.call_anonymous_issue(), era, checkpoint),
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

        let sig_repr =
            RedjubjubSignature::try_from(sig).expect("shoukd be casted from RedjubjubSignature.");
        let uxt =
            UncheckedExtrinsic::new_signed(index, raw_payload.1, sig_vk.into(), sig_repr, era);
        let _tx_hash = api
            .submit_extrinsic(&uxt)
            .expect("Faild to submit a extrinsic to zerochain node.");
    }
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
            zNonce::from_slice(&self.nonce[..]),
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
            zNonce::from_slice(&self.nonce[..]),
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
            zNonce::from_slice(&self.nonce[..]),
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
            zNonce::from_slice(&self.nonce[..]),
        ))
    }

    pub fn call_anonymous_issue(&self) -> Call {
        Call::AnonymousBalances(AnonymousBalancesCall::issue(
            zProof::from_slice(&self.proof[..]),
            zEncKey::from_slice(&self.enc_key_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_amount_recipient[..]),
            zLeftCiphertext::from_slice(&self.left_fee[..]),
            zCiphertext::from_slice(&self.enc_balance[..]),
            zRightCiphertext::from_slice(&self.right_randomness[..]),
            zNonce::from_slice(&self.nonce[..]),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncryptionKey;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use scrypto::jubjub::JubjubBls12;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::Path;

    #[test]
    fn test_gen_proof() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let amount = 10;
        let remaining_balance = 89;
        let balance = 100;
        let fee = 1;

        let sender_seed: [u8; 32] = rng.gen();
        let recipient_seed: [u8; 32] = rng.gen();

        let spending_key = SpendingKey::<Bls12>::from_seed(&sender_seed);
        let enc_key_recipient = EncryptionKey::<Bls12>::from_seed(&recipient_seed, params).unwrap();

        let randomness = rng.gen();
        let enc_key = EncryptionKey::from_seed(&sender_seed[..], params).unwrap();
        let enc_balance = vec![Ciphertext::encrypt(
            balance,
            &randomness,
            &enc_key,
            p_g,
            params,
        )];

        let g_epoch = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proofs = KeyContext::read_from_path(
            "../../zface/params/test_conf_pk.dat",
            "../../zface/params/test_conf_vk.dat",
        )
        .unwrap()
        .gen_proof(
            amount,
            fee,
            remaining_balance,
            0,
            0,
            &spending_key,
            MultiEncKeys::<Bls12, Confidential>::new(enc_key_recipient),
            &enc_balance,
            g_epoch,
            rng,
            params,
        );

        assert!(proofs.is_ok());
    }

    #[test]
    fn test_read_proving_key() {
        let pk_path = Path::new("../../zface/params/test_conf_pk.dat");
        let pk_file = File::open(&pk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        let mut buf = vec![];

        pk_reader.read_to_end(&mut buf).unwrap();
        let _proving_key = Parameters::<Bls12>::read(&mut &buf[..], true).unwrap();
    }

    #[test]
    fn nostd_to_std_read_write() {
        use bellman_verifier::PreparedVerifyingKey as zPreparedVerifyingKey;
        use std::fs::File;
        use std::io::{BufReader, Read};
        use std::path::Path;
        use zpairing::bls12_381::Bls12 as zBls12;

        let vk_path = Path::new("../../core/bellman-verifier/src/tests/verification.params");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        let prepared_vk_a = zPreparedVerifyingKey::<zBls12>::read(&mut &buf_vk[..]).unwrap();

        let mut buf = vec![];
        prepared_vk_a.write(&mut &mut buf).unwrap();

        let prepared_vk_b = PreparedVerifyingKey::<Bls12>::read(&mut &buf[..]).unwrap();

        let mut buf_b = vec![];
        prepared_vk_b.write(&mut &mut buf_b).unwrap();

        assert!(buf_vk == buf);
        assert!(buf_vk == buf_b);
        assert!(buf == buf_b);
    }

    #[test]
    fn std_to_nostd_read_write() {
        use bellman_verifier::PreparedVerifyingKey as zPreparedVerifyingKey;
        use std::fs::File;
        use std::io::{BufReader, Read};
        use std::path::Path;
        use zpairing::bls12_381::Bls12 as zBls12;

        let vk_path = Path::new("../../core/bellman-verifier/src/tests/verification.params");
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        let prepared_vk_a = PreparedVerifyingKey::<Bls12>::read(&mut &buf_vk[..]).unwrap();

        let mut buf = vec![];
        prepared_vk_a.write(&mut &mut buf).unwrap();

        let prepared_vk_b = zPreparedVerifyingKey::<zBls12>::read(&mut &buf[..]).unwrap();

        let mut buf_b = vec![];
        prepared_vk_b.write(&mut &mut buf_b).unwrap();

        assert!(buf == buf_b);
    }
}
