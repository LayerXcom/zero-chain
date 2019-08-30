//! This module contains a circuit implementation for anonymous transfer.
//! The statements are following:
//! Amount check: \sum s_i * C_i = b_1 + \sum r * s_i * y_i ,where b_1: transferred amount
//! Amount check: \sum (s_i + t_i) * C_i = \sum (s_i + t_i) * r * y_i
//! Amount check: (1 - s_i)(1 - t_i) * C = (1 - s_i)(1 - t_i) * r * y_i
//! Randomness check: D = r * G
//! Balance check: \sum s_i * (C_li - C_i) = b_2 * G + sk * (\sum (s_i * C_ri) - D) ,where b_2: remaining balance
//! Secret key check: sk * G = \sum s_i * y_i
//! Nonce check: sk * G_epoch = u
//! Spend authority: rvk = alpha * G + pgk
//! s_i \in {0, 1}
//! t_i \in {0, 1}
//! \sum s_i = 1
//! \sum t_i = 1
//! b_1 \in [0, MAX]
//! b_2 \in [0, MAX]

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};
use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators,
    edwards,
    PrimeOrder,
};
use scrypto::circuit::{
    boolean::self,
    ecc::{self, EdwardsPoint},
};
use crate::{ProofGenerationKey, EncryptionKey, DecryptionKey, elgamal};
use super::{
    range_check::u32_into_bit_vec_le,
    anonimity_set::*,
    utils::*,
};

pub struct AnonymousTransfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub amount: Option<u32>,
    pub remaining_balance: Option<u32>,
    pub s_index: Option<usize>,
    pub t_index: Option<usize>,
    pub randomness: Option<&'a E::Fs>,
    pub alpha: Option<&'a E::Fs>,
    pub proof_generation_key: Option<&'a ProofGenerationKey<E>>,
    pub dec_key: Option<&'a DecryptionKey<E>>,
    pub enc_key_recipient: Option<&'a EncryptionKey<E>>,
    pub enc_key_decoys: Option<&'a [EncryptionKey<E>]>,
    pub enc_balances: Option<&'a [elgamal::Ciphertext<E>]>,
    pub g_epoch: Option<&'a edwards::Point<E, PrimeOrder>>,
}

impl<'a, E: JubjubEngine> Circuit<E> for AnonymousTransfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;

        // the neutral element
        let zero_p = EdwardsPoint::<E>::witness::<PrimeOrder, _>(
            cs.namespace(|| "initialize acc."),
            Some(edwards::Point::zero()),
            params,
        )?;

        // Ensure the amount is u32.
        let amount_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of amount"),
            self.amount
        )?;

        // Multiply the amount to the base point same as FixedGenerators::ElGamal.
        let amount_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the amount in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &amount_bits,
            params
        )?;

        let neg_amount_g = negate_point(
            cs.namespace(|| "negate amount_g"),
            &amount_g,
            params
        )?;

        // Ensure the remaining balance is u32.
        let remaining_balance_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of remaining_balance"),
            self.remaining_balance
        )?;
        // Multiply the remaining balance to the base point same as FixedGenerators::ElGamal.
        let remaining_balance_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the remaining balance in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &remaining_balance_bits,
            params
        )?;

        // dec_key in circuit
        let dec_key_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("dec_key")),
            self.dec_key.map(|e| e.0)
        )?;

        let s_bins = Binary::new(
            cs.namespace(|| "new s binary"),
            ST::S,
            self.s_index
        )?;

        let t_bins = Binary::new(
            cs.namespace(|| "new t binary"),
            ST::T,
            self.t_index
        )?;

        let mut enc_key_set = EncKeySet::new(ANONIMITY_SIZE);
        enc_key_set
            .push_enckeys(
                cs.namespace(|| "push enckeys"),
                &dec_key_bits,
                self.enc_key_recipient,
                self.enc_key_decoys,
                self.s_index,
                self.t_index,
                params
            )?;

        let expected_enc_key_sender = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded enc keys"),
            &enc_key_set.0,
            zero_p.clone(),
            params
        )?;

        if let Some(i) = self.s_index {
            eq_edwards_points(
                cs.namespace(|| "equal enc_key_sender"),
                &expected_enc_key_sender,
                &enc_key_set.0[i]
            )?;
        }

        // Multiply randomness to all enc keys: \sum r * y_i
        let enc_keys_mul_random = enc_key_set.gen_enc_keys_mul_random(
            cs.namespace(|| "generate enc keys multipled by randomness"),
            self.randomness,
            params
        )?;

        // Evaluate by the s_i binaries: \sum s_i * r * y_i
        let enc_keys_random_fold_s_i = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded enc keys mul random"),
            &enc_keys_mul_random.0,
            zero_p.clone(),
            params
        )?;

        // Add amount * G: b_1 + \sum r * s_i * y_i
        let expected_ciphertext_left_s_i = enc_keys_random_fold_s_i.add(
            cs.namespace(|| "compute ciphertext left s_i"),
            &amount_g,
            params
        )?;

        // Generate all ciphertexts of left components: \sum C_i
        let ciphertext_left_set= enc_keys_mul_random.gen_left_ciphertexts(
            cs.namespace(|| "compute left ciphertexts of s_i"),
            &amount_g,
            &neg_amount_g,
            self.s_index,
            self.t_index,
            zero_p.clone(),
            params
        )?;

        // Evaluate by the s_i binaries: \sum s_i * C_i
        let ciphertext_left_s_i = s_bins.edwards_add_fold(
            cs.namespace(|| "add folded left ciphertext based in s_i"),
            &ciphertext_left_set.0,
            zero_p.clone(),
            params
        )?;

        // Amount check: \sum s_i * C_i = b_1 + \sum r * s_i * y_i
        eq_edwards_points(
            cs.namespace(|| "left ciphertext equals based in s_i"),
            &expected_ciphertext_left_s_i,
            &ciphertext_left_s_i
        )?;

        {
            let xor_st_bins = s_bins.xor(cs.namespace(|| "s_i xor t_i"), &t_bins)?;

            // Evaluate by the (s_i + t_i) binaries: \sum (s_i + t_i) * C_i
            let enc_keys_random_fold_s_xor_t = xor_st_bins.edwards_add_fold(
                cs.namespace(|| "add folded randomized enc keys based in (s_i xor t_i)"),
                &enc_keys_mul_random.0,
                zero_p.clone(),
                params
            )?;

            // Evaluate by the (s_i + t_i) binaries: \sum (s_i + t_i) * C_i
            let ciphertext_left_s_xor_t = xor_st_bins.edwards_add_fold(
                cs.namespace(|| "add folded left ciphertext based in (s_i xor t_i)"),
                &ciphertext_left_set.0,
                zero_p.clone(),
                params
            )?;

            // Amount check: \sum (s_i + t_i) * C_i = \sum (s_i + t_i) * r * y_i
            eq_edwards_points(
                cs.namespace(|| "left ciphertext equals based in (s_i xor t_i)"),
                &ciphertext_left_s_xor_t,
                &enc_keys_random_fold_s_xor_t
            )?;

            let nor_st_bins = s_bins.nor(cs.namespace(|| "s_i nor t_i"), &t_bins)?;

            // Amount check: (1 - s_i)(1 - t_i) * C = (1 - s_i)(1 - t_i) * r * y_i
            nor_st_bins.conditionally_equals(
                cs.namespace(|| "equal a and b in nor st"),
                &ciphertext_left_set.0,
                &enc_keys_mul_random.0
            )?;
        }

        enc_key_set.inputize(cs.namespace(|| "inputize enc key set"))?;
        ciphertext_left_set.inputize(cs.namespace(|| "inputize ciphertext left set"))?;

        // balance integrity
        {
            // Negate amount ciphertexts of left components
            let neg_left_amount_cipher = ciphertext_left_set.neg_each(
                cs.namespace(|| "negate left amount ciphertexts"),
                params
            )?;

            // Witness current balance ciphertexts of left components
            let left_balance_ciphertexts = LeftBalanceCiphertexts::witness::<PrimeOrder, _>(
                cs.namespace(|| "left balance ciphertexts witness"),
                self.enc_balances,
                params
            )?;

            // Compute left balance ciphertexts minus left amount ciphertexts : C_li - C_i
            let added_lefts = left_balance_ciphertexts.add_each(
                cs.namespace(|| "add each with left amount ciphertexts"),
                &neg_left_amount_cipher,
                params
            )?;

            //  Evaluate by the s_i binaries: \sum s_i * (C_li - C_i)
            let lh_c = s_bins.edwards_add_fold(
                cs.namespace(|| "Add folded C_l minus C"),
                &added_lefts.0,
                zero_p.clone(),
                params
            )?;

            // Witness current balance ciphertexts of right components
            let right_balance_ciphertects = RightBalanceCiphertexts::witness::<PrimeOrder, _>(
                cs.namespace(|| "right balance ciphertexts witness"),
                self.enc_balances,
                params
            )?;

            // Evaluate by the s_i binaries: \sum (s_i * C_ri)
            let right_balance_cipher_fold = s_bins.edwards_add_fold(
                cs.namespace(|| "add folded right balance ciphertexts"),
                &right_balance_ciphertects.0,
                zero_p.clone(),
                params
            )?;

            // Generate the randomness for elgamal encryption into the circuit
            let randomness_bits = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "randomness_bits"),
                self.randomness.map(|e| *e)
            )?;

            // Multiply the randomness to the base point
            let right_ciphertext = ecc::fixed_base_multiplication(
                cs.namespace(|| format!("compute the right elgamal component")),
                FixedGenerators::NoteCommitmentRandomness,
                &randomness_bits,
                params
            )?;

            // Negate amount ciphertexts of right components
            let neg_right_ciphertext = negate_point(
                cs.namespace(|| "negate right ciphertext"),
                &right_ciphertext,
                params
            )?;

            // Subtract right ciphertexts: \sum (s_i * C_ri) - D
            let cr_minus_d = right_balance_cipher_fold.add(
                cs.namespace(|| "amount minus balance ciphertext"),
                &neg_right_ciphertext,
                params
            )?;

            // Multiply dec_key: sk * (\sum (s_i * C_ri) - D)
            let cr_minus_d_mul_sk = cr_minus_d.mul(
                cs.namespace(|| "cr_minus_d mul sk"),
                &dec_key_bits,
                params
            )?;

            // Add remaining_balance * G :b_2 * G + sk * (\sum (s_i * C_ri) - D)
            let rh_c = remaining_balance_g.add(
                cs.namespace(|| "rb_g adds cr_minus_d_mul_sk"),
                &cr_minus_d_mul_sk,
                params
            )?;

            // Balance check: \sum s_i * (C_li - C_i) = b_2 * G + sk * (\sum s_i * C_ri - D)
            eq_edwards_points(
                cs.namespace(|| "rl_c equals to rh_c"),
                &lh_c,
                &rh_c
            )?;

            left_balance_ciphertexts.inputize(cs.namespace(|| "inputize left balance ciphertext"))?;
            right_balance_ciphertects.inputize(cs.namespace(|| "inputize right balance ciphertext"))?;
            right_ciphertext.inputize(cs.namespace(|| "inputize right amount ciphertext."))?;
        }

        // Inputize re-randomized signature verification key
        rvk_inputize(
            cs.namespace(|| "inputize rvk"),
            self.proof_generation_key,
            self.alpha,
            params
        )?;

        // Inputize g_epoch and nonce
        g_epoch_nonce_inputize(
            cs.namespace(|| "inputize g_epoch and nonce"),
            self.g_epoch,
            &dec_key_bits,
            params
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::{bls12_381::{Bls12, Fr}, Field};
    use rand::{SeedableRng, Rng, XorShiftRng, Rand};
    use crate::EncryptionKey;
    use crate::circuit::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs::Fs, JubjubParams};

    fn neg_encrypt(
        amount: u32,
        randomness: &Fs,
        enc_key: &EncryptionKey<Bls12>,
        p_g: FixedGenerators,
        params: &JubjubBls12
    ) -> elgamal::Ciphertext<Bls12> {
        let right = params.generator(p_g).mul(*randomness, params);
        let v_point = params.generator(p_g).mul(amount as u64, params).negate();
        let r_point = enc_key.0.mul(*randomness, params);
        let left = v_point.add(&r_point, params);

        elgamal::Ciphertext {
            left,
            right,
        }
    }

    fn test_based_amount(amount: u32) {
        // constants
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let current_balance_sender = 100;
        let remaining_balance = 90;

        // randomness
        let seed_sender: [u8; 32] = rng.gen();
        let seed_recipient: [u8; 32] = rng.gen();
        let alpha = Fs::rand(rng);
        let randomness_amount = Fs::rand(rng);
        let randomness_balanace_sender = Fs::rand(rng);
        let randomness_balanace_recipient = Fs::rand(rng);
        let current_balance_recipient: u32 = rng.gen();
        let s_index: usize = rng.gen_range(0, ANONIMITY_SIZE+1);
        let mut t_index: usize;
        loop {
            t_index = rng.gen_range(0, ANONIMITY_SIZE+1);
            if t_index != s_index {
                break;
            }
        }
        let seed_decoys_iter = rng.gen_iter::<[u8; 32]>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let randomness_balances_iter = rng.gen_iter::<Fs>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let current_balance_iter = rng.gen_iter::<u32>().take(DECOY_SIZE);
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // keys
        let proof_gen_key = ProofGenerationKey::<Bls12>::from_seed(&seed_sender[..], params);
        let dec_key = proof_gen_key.into_decryption_key().unwrap();
        let enc_key_sender = EncryptionKey::from_decryption_key(&dec_key, params);
        let enc_key_recipient = EncryptionKey::<Bls12>::from_seed(&seed_recipient, params).unwrap();
        let enc_keys_decoy = seed_decoys_iter.map(|e| EncryptionKey::from_seed(&e, params).ok())
            .collect::<Vec<Option<EncryptionKey<Bls12>>>>();
        let mut enc_keys = enc_keys_decoy.clone();
        enc_keys.insert(s_index, Some(enc_key_sender.clone()));
        enc_keys.insert(t_index, Some(enc_key_recipient.clone()));

        // ciphertexts
        let left_ciphertext_amount_sender = elgamal::Ciphertext::encrypt(amount, &randomness_amount, &enc_key_sender, p_g, params).left;
        let left_ciphertext_amount_recipient = neg_encrypt(amount, &randomness_amount, &enc_key_recipient, p_g, params).left;
        let left_ciphertexts_amount_decoy = enc_keys_decoy.iter()
            .map(|e| Some(elgamal::Ciphertext::encrypt(0, &randomness_amount, e.as_ref().unwrap(), p_g, params).left))
            .collect::<Vec<Option<edwards::Point<Bls12, PrimeOrder>>>>();
        let mut left_ciphertexts_amount = left_ciphertexts_amount_decoy.clone();
        left_ciphertexts_amount.insert(s_index, Some(left_ciphertext_amount_sender));
        left_ciphertexts_amount.insert(t_index, Some(left_ciphertext_amount_recipient));
        let right_ciphertext_amount = elgamal::Ciphertext::encrypt(amount, &randomness_amount, &enc_key_sender, p_g, params).right;

        let ciphertext_balance_sender =
            elgamal::Ciphertext::encrypt(current_balance_sender, &randomness_balanace_sender, &enc_key_sender, p_g, params);
        let ciphertext_balance_recipient =
            elgamal::Ciphertext::encrypt(current_balance_recipient, &randomness_balanace_recipient, &enc_key_recipient, p_g, params);
        let mut ciphertext_balances = enc_keys_decoy.iter().zip(current_balance_iter).zip(randomness_balances_iter)
            .map(|((e, a), r)| Some(elgamal::Ciphertext::encrypt(a, &r, e.as_ref().unwrap(), p_g, params)))
            .collect::<Vec<Option<elgamal::Ciphertext<Bls12>>>>();
        ciphertext_balances.insert(s_index, Some(ciphertext_balance_sender));
        ciphertext_balances.insert(t_index, Some(ciphertext_balance_recipient));
        let left_ciphertext_balances = ciphertext_balances.clone().into_iter().map(|e| e.unwrap().left)
            .collect::<Vec<edwards::Point<Bls12, PrimeOrder>>>();
        let right_ciphertext_balances = ciphertext_balances.clone().into_iter().map(|e| e.unwrap().right)
            .collect::<Vec<edwards::Point<Bls12, PrimeOrder>>>();

        // rvk and nonce
        let rvk = proof_gen_key.into_rvk(alpha, params).0.into_xy();
        let g_epoch = edwards::Point::<Bls12, _>::rand(rng, params).mul_by_cofactor(params);
        let g_epoch_xy = g_epoch.into_xy();
        let nonce_xy = g_epoch.mul(dec_key.0, params).into_xy();

        // cs test
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let instance = AnonymousTransfer {
            params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            s_index: Some(s_index),
            t_index: Some(t_index),
            randomness: Some(&randomness_amount),
            alpha: Some(&alpha),
            proof_generation_key: Some(&proof_gen_key),
            dec_key: Some(&dec_key),
            enc_key_recipient: Some(&enc_key_recipient),
            enc_key_decoys: None,
            enc_balances: None,
            g_epoch: Some(&g_epoch),
        };

        instance.synthesize(&mut cs).unwrap();
        assert!(cs.is_satisfied());
        assert_eq!(cs.num_constraints(), 47265);
        assert_eq!(cs.hash(), "c9c3d48fff65f07b39ac2edbc21da671c5b1c7d9cb9d85b2b92e7deb90eab991");
        assert_eq!(cs.num_inputs(), 97);
        println!("num: {:?}", cs.num_constraints());
        println!("hash: {:?}", cs.hash());
        println!("num_inputs: {:?}", cs.num_inputs());

        let len = enc_keys.len();
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        for (i, enc_key) in enc_keys.into_iter().map(|e| e.unwrap().0).enumerate() {
            assert_eq!(cs.get_input((i+1) * 2 - 1, &format!("inputize enc key set/inputize enc keys {}/x/input variable", i)), enc_key.into_xy().0);
            assert_eq!(cs.get_input((i+1) * 2, &format!("inputize enc key set/inputize enc keys {}/y/input variable", i)), enc_key.into_xy().1);
        }
        for (i, lca) in left_ciphertexts_amount.into_iter().map(|e| e.unwrap()).enumerate() {
            assert_eq!(cs.get_input((len+i+1) * 2 - 1, &format!("inputize ciphertext left set/inputize left ciphertexts {}/x/input variable", i)), lca.into_xy().0);
            assert_eq!(cs.get_input((len+i+1) * 2, &format!("inputize ciphertext left set/inputize left ciphertexts {}/y/input variable", i)), lca.into_xy().1);
        }
        for (i, lcb) in left_ciphertext_balances.into_iter().map(|e| e).enumerate() {
            assert_eq!(cs.get_input((i+1) * 2 - 1 + len*4, &format!("inputize left balance ciphertext/inputize left balance ciphertexts {}/x/input variable", i)), lcb.into_xy().0);
            assert_eq!(cs.get_input((i+1) * 2 + len*4, &format!("inputize left balance ciphertext/inputize left balance ciphertexts {}/y/input variable", i)), lcb.into_xy().1);
        }
        for (i, rcb) in right_ciphertext_balances.into_iter().map(|e| e).enumerate() {
            assert_eq!(cs.get_input((i+1) * 2 - 1 + len*6, &format!("inputize right balance ciphertext/inputize right balance ciphertexts {}/x/input variable", i)), rcb.into_xy().0);
            assert_eq!(cs.get_input((i+1) * 2 + len*6, &format!("inputize right balance ciphertext/inputize right balance ciphertexts {}/y/input variable", i)), rcb.into_xy().1);
        }
        assert_eq!(cs.get_input(len*8+1, &format!("inputize right amount ciphertext./x/input variable")), right_ciphertext_amount.into_xy().0);
        assert_eq!(cs.get_input(len*8+2, &format!("inputize right amount ciphertext./y/input variable")), right_ciphertext_amount.into_xy().1);
        assert_eq!(cs.get_input(len*8+3, &format!("inputize rvk/rvk/x/input variable")), rvk.0);
        assert_eq!(cs.get_input(len*8+4, &format!("inputize rvk/rvk/y/input variable")), rvk.1);
        assert_eq!(cs.get_input(len*8+5, &format!("inputize g_epoch and nonce/inputize g_epoch/x/input variable")), g_epoch_xy.0);
        assert_eq!(cs.get_input(len*8+6, &format!("inputize g_epoch and nonce/inputize g_epoch/y/input variable")), g_epoch_xy.1);
        assert_eq!(cs.get_input(len*8+7, &format!("inputize g_epoch and nonce/inputize nonce/x/input variable")), nonce_xy.0);
        assert_eq!(cs.get_input(len*8+8, &format!("inputize g_epoch and nonce/inputize nonce/y/input variable")), nonce_xy.1);
    }

    #[test]
    fn test_circuit_anonymous_transfer_valid() {
        test_based_amount(10);
    }
    #[should_panic]
    #[test]
    fn test_circuit_anonymous_transfer_invalid() {
        test_based_amount(11);
    }
}
