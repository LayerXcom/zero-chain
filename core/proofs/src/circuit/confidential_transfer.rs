//! This module contains a circuit implementation for confidential transfer.
//! The statement is following.
//! * Range check of the transferred amount
//! * Range check of the sender's balance
//! * Validity of public key
//! * Validity of encryption for transferred amount
//! * Validity of encryption for sender's balance
//! * Spend authority proof
//! * Some small order checks

use super::{range_check::u32_into_bit_vec_le, utils::*};
use crate::elgamal::Ciphertext;
use crate::{DecryptionKey, EncryptionKey, ProofGenerationKey};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use scrypto::circuit::{boolean, ecc};
use scrypto::jubjub::{edwards, PrimeOrder};
use scrypto::jubjub::{FixedGenerators, JubjubEngine};

pub struct ConfidentialTransfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub amount: Option<u32>,
    pub remaining_balance: Option<u32>,
    pub randomness: Option<&'a E::Fs>,
    pub alpha: Option<&'a E::Fs>,
    pub proof_generation_key: Option<&'a ProofGenerationKey<E>>,
    pub dec_key_sender: Option<&'a DecryptionKey<E>>,
    pub enc_key_recipient: Option<&'a EncryptionKey<E>>,
    pub encrypted_balance: Option<&'a Ciphertext<E>>,
    pub fee: Option<u32>,
    pub g_epoch: Option<&'a edwards::Point<E, PrimeOrder>>,
}

impl<'a, E: JubjubEngine> ConfidentialTransfer<'a, E> {
    pub fn new(params: &'a E::Params) -> Self {
        ConfidentialTransfer {
            params,
            amount: None,
            remaining_balance: None,
            randomness: None,
            alpha: None,
            proof_generation_key: None,
            dec_key_sender: None,
            enc_key_recipient: None,
            encrypted_balance: None,
            fee: None,
            g_epoch: None,
        }
    }
}

impl<'a, E: JubjubEngine> Circuit<E> for ConfidentialTransfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;

        // Ensure the amount is u32.
        let amount_bits =
            u32_into_bit_vec_le(cs.namespace(|| "range proof of amount"), self.amount)?;

        // Ensure the remaining balance is u32.
        let remaining_balance_bits = u32_into_bit_vec_le(
            cs.namespace(|| "range proof of remaining_balance"),
            self.remaining_balance,
        )?;

        // Ensure the fee is u32.
        let fee_bits = u32_into_bit_vec_le(cs.namespace(|| "range proof of fee"), self.fee)?;

        // dec_key_sender in circuit
        let dec_key_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("dec_key_sender")),
            self.dec_key_sender.map(|e| e.0),
        )?;

        // Ensure the validity of enc_key_sender
        let enc_key_sender_bits = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute enc_key_sender")),
            FixedGenerators::NoteCommitmentRandomness,
            &dec_key_bits,
            params,
        )?;

        // Expose the enc_key_sender publicly
        enc_key_sender_bits.inputize(cs.namespace(|| format!("inputize enc_key_sender")))?;

        // Multiply the amount to the base point same as FixedGenerators::ElGamal.
        let amount_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the amount in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &amount_bits,
            params,
        )?;

        // Multiply the fee to the base point same as FixedGenerators::ElGamal.
        let fee_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the fee in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &fee_bits,
            params,
        )?;

        // Generate the randomness for elgamal encryption into the circuit
        let randomness_bits = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("randomness_bits")),
            self.randomness.map(|e| *e),
        )?;

        // Generate the randomness * enc_key_sender in circuit
        let val_rls = enc_key_sender_bits.mul(
            cs.namespace(|| format!("compute sender amount cipher")),
            &randomness_bits,
            params,
        )?;

        // Ensures recipient enc_key is on the curve
        let enc_key_recipient_bits = ecc::EdwardsPoint::witness(
            cs.namespace(|| "recipient enc_key witness"),
            self.enc_key_recipient.as_ref().map(|e| e.0.clone()),
            params,
        )?;

        // Check the recipient enc_key is not small order
        enc_key_recipient_bits
            .assert_not_small_order(cs.namespace(|| "val_gl not small order"), params)?;

        // Generate the randomness * enc_key_recipient in circuit
        let val_rlr = enc_key_recipient_bits.mul(
            cs.namespace(|| format!("compute recipient amount cipher")),
            &randomness_bits,
            params,
        )?;

        enc_key_recipient_bits.inputize(cs.namespace(|| format!("inputize enc_key_recipient")))?;

        // Generate the left elgamal component for sender in circuit
        let c_left_sender = amount_g.add(
            cs.namespace(|| format!("computation of sender's c_left")),
            &val_rls,
            params,
        )?;

        // Generate the left elgamal component for recipient in circuit
        let c_left_recipient = amount_g.add(
            cs.namespace(|| format!("computation of recipient's c_left")),
            &val_rlr,
            params,
        )?;

        // Multiply the randomness to the base point same as FixedGenerators::ElGamal.
        let c_right = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the right elgamal component")),
            FixedGenerators::NoteCommitmentRandomness,
            &randomness_bits,
            params,
        )?;

        let f_left_sender = fee_g.add(
            cs.namespace(|| format!("computation of sender's f_left")),
            &val_rls,
            params,
        )?;

        // Expose the ciphertext publicly.
        c_left_sender.inputize(cs.namespace(|| format!("c_left_sender")))?;
        c_left_recipient.inputize(cs.namespace(|| format!("c_left_recipient")))?;
        c_right.inputize(cs.namespace(|| format!("c_right")))?;
        f_left_sender.inputize(cs.namespace(|| format!("f_left_sender")))?;

        // The balance encryption validity.
        // It is a bit complicated bacause we can not know the randomness of balance.
        //
        // Enc_sender(sender_balance).cl - Enc_sender(amount).cl - Enc_sender(fee).cl
        //      == (remaining_balance)G + dec_key_sender * (Enc_sender(sender_balance).cr - (random)G - (random)G)
        // <==>
        // Enc_sender(sender_balance).cl + dec_key_sender * (random)G + dec_key_sender * (random)G
        //      == (remaining_balance)G + dec_key_sender * Enc_sender(sender_balance).cr + Enc_sender(amount).cl + Enc_sender(fee).cl
        {
            let enc_balance_left = ecc::EdwardsPoint::witness(
                cs.namespace(|| "encrypted balance left"),
                self.encrypted_balance.as_ref().map(|e| e.left.clone()),
                params,
            )?;

            let enc_balance_right = ecc::EdwardsPoint::witness(
                cs.namespace(|| "encrypted balance right"),
                self.encrypted_balance.as_ref().map(|e| e.right.clone()),
                params,
            )?;

            // TODO:
            enc_balance_left.assert_not_small_order(
                cs.namespace(|| "enc_balance_left isn't small order"),
                params,
            )?;
            enc_balance_right.assert_not_small_order(
                cs.namespace(|| "enc_balance_right isn't small order"),
                params,
            )?;

            //  dec_key_sender * (random)G
            let dec_key_sender_random = c_right.mul(
                cs.namespace(|| format!("c_right mul by dec_key_sender")),
                &dec_key_bits,
                params,
            )?;

            // Enc_sender(sender_balance).cl + dec_key_sender * (random)G
            let balance_dec_key_sender_random = enc_balance_left.add(
                cs.namespace(|| format!("enc_balance_left add dec_key_sender_pointl")),
                &dec_key_sender_random,
                params,
            )?;

            // Enc_sender(sender_balance).cl + dec_key_sender * (random)G + dec_key_sender * (random)G
            let bi_left = balance_dec_key_sender_random.add(
                cs.namespace(|| format!("pointl readd dec_key_sender_pointl")),
                &dec_key_sender_random,
                params,
            )?;

            // dec_key_sender * Enc_sender(sender_balance).cr
            let dec_key_sender_pointr = enc_balance_right.mul(
                cs.namespace(|| format!("c_right_sender mul by dec_key_sender")),
                &dec_key_bits,
                params,
            )?;

            // Compute (remaining_balance)G
            let rem_bal_g = ecc::fixed_base_multiplication(
                cs.namespace(|| format!("compute the remaining balance in the exponent")),
                FixedGenerators::NoteCommitmentRandomness,
                &remaining_balance_bits,
                params,
            )?;

            // Enc_sender(amount).cl + (remaining_balance)G
            let val_rem_bal = c_left_sender.add(
                cs.namespace(|| format!("c_left_sender add rem_bal_g")),
                &rem_bal_g,
                params,
            )?;

            // Enc_sender(amount).cl + (remaining_balance)G + dec_key_sender * Enc_sender(sender_balance).cr
            let val_rem_bal_balr = val_rem_bal.add(
                cs.namespace(|| format!("val_rem_bal add ")),
                &dec_key_sender_pointr,
                params,
            )?;

            // Enc_sender(amount).cl + (remaining_balance)G + dec_key_sender * Enc_sender(sender_balance).cr + Enc_sender(fee).cl
            let bi_right = f_left_sender.add(
                cs.namespace(|| format!("f_left_sender add")),
                &val_rem_bal_balr,
                params,
            )?;

            eq_edwards_points(
                cs.namespace(|| "equal two edwards poinsts"),
                &bi_left,
                &bi_right,
            )?;

            enc_balance_left.inputize(cs.namespace(|| format!("inputize enc_balance_left")))?;
            enc_balance_right.inputize(cs.namespace(|| format!("inputize enc_balance_right")))?;
        }

        rvk_inputize(
            cs.namespace(|| "inputize rvk"),
            self.proof_generation_key,
            self.alpha,
            params,
        )?;

        g_epoch_nonce_inputize(
            cs.namespace(|| "inputize g_epoch and nonce"),
            self.g_epoch,
            &dec_key_bits,
            params,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::TestConstraintSystem;
    use crate::EncryptionKey;
    use pairing::{
        bls12_381::{Bls12, Fr},
        Field,
    };
    use rand::{Rand, Rng, SeedableRng, XorShiftRng};
    use scrypto::jubjub::{fs::Fs, JubjubBls12};

    fn test_based_amount(amount: u32) {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let seed_sender: [u8; 32] = rng.gen();
        let seed_recipient: [u8; 32] = rng.gen();

        let proof_gen_key = ProofGenerationKey::<Bls12>::from_seed(&seed_sender[..], params);
        let dec_key = proof_gen_key.into_decryption_key().unwrap();

        let enc_key_sender = EncryptionKey::from_decryption_key(&dec_key, params);
        let enc_key_recipient = EncryptionKey::from_seed(&seed_recipient, params).unwrap();
        let enc_key_sender_xy = enc_key_sender.0.into_xy();
        let enc_key_recipient_xy = enc_key_recipient.0.into_xy();

        let alpha: Fs = rng.gen();

        let fee = 1;
        let current_balance = 27;
        let remaining_balance = 16;

        let randomness_balance = Fs::rand(rng);
        let randomness_amount = Fs::rand(rng);

        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let ciphetext_balance = Ciphertext::encrypt(
            current_balance,
            &randomness_balance,
            &enc_key_sender,
            p_g,
            params,
        );

        let c_bal_left = ciphetext_balance.left.into_xy();
        let c_bal_right = ciphetext_balance.right.into_xy();

        let ciphertext_amount_sender =
            Ciphertext::encrypt(amount, &randomness_amount, &enc_key_sender, p_g, params);
        let c_val_s_left = ciphertext_amount_sender.left.into_xy();
        let c_val_right = ciphertext_amount_sender.right.into_xy();

        let ciphertext_fee_sender =
            Ciphertext::encrypt(fee, &randomness_amount, &enc_key_sender, p_g, params);
        let c_fee_s_left = ciphertext_fee_sender.left.into_xy();

        let ciphertext_amount_recipient =
            Ciphertext::encrypt(amount, &randomness_amount, &enc_key_recipient, p_g, params);
        let c_val_r_left = ciphertext_amount_recipient.left.into_xy();

        let rvk = proof_gen_key.into_rvk(alpha, params).0.into_xy();
        let g_epoch = edwards::Point::rand(rng, params).mul_by_cofactor(params);
        let g_epoch_xy = g_epoch.into_xy();
        let nonce = g_epoch.mul(dec_key.0, params).into_xy();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = ConfidentialTransfer {
            params,
            amount: Some(amount),
            remaining_balance: Some(remaining_balance),
            randomness: Some(&randomness_amount),
            alpha: Some(&alpha),
            proof_generation_key: Some(&proof_gen_key),
            dec_key_sender: Some(&dec_key),
            enc_key_recipient: Some(&enc_key_recipient),
            encrypted_balance: Some(&ciphetext_balance),
            fee: Some(fee),
            g_epoch: Some(&g_epoch),
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied());
        // println!("num: {:?}", cs.num_constraints());
        // println!("hash: {:?}", cs.hash());

        assert_eq!(cs.num_constraints(), 19974);
        assert_eq!(
            cs.hash(),
            "d23c92fb60ee547d45118e160679929cfa186957280673af62f09fa12d401784"
        );

        assert_eq!(cs.num_inputs(), 23);
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(
            cs.get_input(1, "inputize enc_key_sender/x/input variable"),
            enc_key_sender_xy.0
        );
        assert_eq!(
            cs.get_input(2, "inputize enc_key_sender/y/input variable"),
            enc_key_sender_xy.1
        );
        assert_eq!(
            cs.get_input(3, "inputize enc_key_recipient/x/input variable"),
            enc_key_recipient_xy.0
        );
        assert_eq!(
            cs.get_input(4, "inputize enc_key_recipient/y/input variable"),
            enc_key_recipient_xy.1
        );
        assert_eq!(
            cs.get_input(5, "c_left_sender/x/input variable"),
            c_val_s_left.0
        );
        assert_eq!(
            cs.get_input(6, "c_left_sender/y/input variable"),
            c_val_s_left.1
        );
        assert_eq!(
            cs.get_input(7, "c_left_recipient/x/input variable"),
            c_val_r_left.0
        );
        assert_eq!(
            cs.get_input(8, "c_left_recipient/y/input variable"),
            c_val_r_left.1
        );
        assert_eq!(cs.get_input(9, "c_right/x/input variable"), c_val_right.0);
        assert_eq!(cs.get_input(10, "c_right/y/input variable"), c_val_right.1);
        assert_eq!(
            cs.get_input(11, "f_left_sender/x/input variable"),
            c_fee_s_left.0
        );
        assert_eq!(
            cs.get_input(12, "f_left_sender/y/input variable"),
            c_fee_s_left.1
        );
        assert_eq!(
            cs.get_input(13, "inputize enc_balance_left/x/input variable"),
            c_bal_left.0
        );
        assert_eq!(
            cs.get_input(14, "inputize enc_balance_left/y/input variable"),
            c_bal_left.1
        );
        assert_eq!(
            cs.get_input(15, "inputize enc_balance_right/x/input variable"),
            c_bal_right.0
        );
        assert_eq!(
            cs.get_input(16, "inputize enc_balance_right/y/input variable"),
            c_bal_right.1
        );
        assert_eq!(cs.get_input(17, "inputize rvk/rvk/x/input variable"), rvk.0);
        assert_eq!(cs.get_input(18, "inputize rvk/rvk/y/input variable"), rvk.1);
        assert_eq!(
            cs.get_input(
                19,
                "inputize g_epoch and nonce/inputize g_epoch/x/input variable"
            ),
            g_epoch_xy.0
        );
        assert_eq!(
            cs.get_input(
                20,
                "inputize g_epoch and nonce/inputize g_epoch/y/input variable"
            ),
            g_epoch_xy.1
        );
        assert_eq!(
            cs.get_input(
                21,
                "inputize g_epoch and nonce/inputize nonce/x/input variable"
            ),
            nonce.0
        );
        assert_eq!(
            cs.get_input(
                22,
                "inputize g_epoch and nonce/inputize nonce/y/input variable"
            ),
            nonce.1
        );
    }

    #[test]
    fn test_circuit_transfer_valid() {
        test_based_amount(10);
    }

    #[test]
    #[should_panic]
    fn test_circuit_transfer_invalid() {
        test_based_amount(11);
    }
}
