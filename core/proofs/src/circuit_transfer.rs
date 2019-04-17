use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};
use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators,
    PrimeOrder,
    edwards
};
use crate::primitives::{
    ProofGenerationKey,
};
use scrypto::circuit::{
    boolean::{self, Boolean},
    ecc::{self, EdwardsPoint},
    num::AllocatedNum,
};
use crate::{elgamal::Ciphertext, Assignment};

// An instance of the Transfer circuit.
pub struct Transfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,
    pub value: Option<u32>,
    pub remaining_balance: Option<u32>,
    pub randomness: Option<E::Fs>,
    pub alpha: Option<E::Fs>,
    pub proof_generation_key: Option<ProofGenerationKey<E>>,
    pub decryption_key: Option<E::Fs>,
    pub pk_d_recipient: Option<edwards::Point<E, PrimeOrder>>,
    pub encrypted_balance: Option<Ciphertext<E>>,
    pub fee: Option<u32>,
}

impl<'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;

        // Ensure the value is u32.
        let value_bits = u32_into_boolean_vec_le(
            cs.namespace(|| "range proof of value"),
            self.value
        )?;

        // Ensure the remaining balance is u32.
        let rem_bal_bits = u32_into_boolean_vec_le(
            cs.namespace(|| "range proof of remaining_balance"),
            self.remaining_balance
        )?;

        //Ensure the fee is u32.
        let fee_bits = u32_into_boolean_vec_le(
            cs.namespace(|| "range proof of fee"),
            self.fee
        )?;

        // decryption_key in circuit
        let decryption_key_v = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("decryption_key")),
            self.decryption_key
        )?;

        // Ensure the validity of pk_d_sender
        let pk_d_sender_v = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute pk_d_sender")),
            FixedGenerators::NoteCommitmentRandomness,
            &decryption_key_v,
            params
        )?;

        // Expose the pk_d_sender publicly
        pk_d_sender_v.inputize(cs.namespace(|| format!("inputize pk_d_sender")))?;

        // Multiply the value to the base point same as FixedGenerators::ElGamal.
        let value_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the value in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &value_bits,
            params
        )?;

        // Multiply the fee to the base point same as FixedGenerators::ElGamal.
        let fee_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the fee in the exponent")),
            FixedGenerators::NoteCommitmentRandomness,
            &fee_bits,
            params
        )?;

        // Generate the randomness into the circuit
        let rcv = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("rcv")),
            self.randomness
        )?;

        // Generate the randomness * pk_d_sender in circuit
        let val_rls = pk_d_sender_v.mul(
            cs.namespace(|| format!("compute sender value cipher")),
            &rcv,
            params
        )?;

        let fee_rls = pk_d_sender_v.mul(
            cs.namespace(|| format!("compute sender fee cipher")),
            &rcv,
            params
        )?;

        // Ensures recipient pk_d is on the curve
        let recipient_pk_d_v = ecc::EdwardsPoint::witness(
            cs.namespace(|| "recipient pk_d witness"),
            self.pk_d_recipient.as_ref().map(|e| e.clone()),
            params
        )?;

        // Check the recipient pk_d is not small order
        recipient_pk_d_v.assert_not_small_order(
            cs.namespace(|| "val_gl not small order"),
            params
        )?;

        // Generate the randomness * pk_d_recipient in circuit
        let val_rlr = recipient_pk_d_v.mul(
            cs.namespace(|| format!("compute recipient value cipher")),
            &rcv,
            params
        )?;

        recipient_pk_d_v.inputize(cs.namespace(|| format!("inputize pk_d_recipient")))?;


        // Generate the left elgamal component for sender in circuit
        let c_left_sender = value_g.add(
            cs.namespace(|| format!("computation of sender's c_left")),
            &val_rls,
            params
        )?;

        // Generate the left elgamal component for recipient in circuit
        let c_left_recipient = value_g.add(
            cs.namespace(|| format!("computation of recipient's c_left")),
            &val_rlr,
            params
        )?;

        // Multiply the randomness to the base point same as FixedGenerators::ElGamal.
        let c_right = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the right elgamal component")),
            FixedGenerators::NoteCommitmentRandomness,
            &rcv,
            params
        )?;

        let f_left_sender = fee_g.add(
            cs.namespace(|| format!("computation of sender's f_left")),
            &fee_rls,
            params
        )?;

        // Expose the ciphertext publicly.
        c_left_sender.inputize(cs.namespace(|| format!("c_left_sender")))?;
        c_left_recipient.inputize(cs.namespace(|| format!("c_left_recipient")))?;
        c_right.inputize(cs.namespace(|| format!("c_right")))?;
        f_left_sender.inputize(cs.namespace(|| format!("f_left_sender")))?;


        // The balance encryption validity.
        // It is a bit complicated bacause we can not know the randomness of balance.
        // Enc_sender(sender_balance).cl - Enc_sender(value).cl
        //     == (remaining_balance)G + decryption_key(Enc_sender(sender_balance).cr - (random)G)
        // <==> Enc_sender(sender_balance).cl + decryption_key * (random)G
        //       == (remaining_balance)G + decryption_key * Enc_sender(sender_balance).cr + Enc_sender(value).cl
        //
        // Enc_sender(sender_balance).cl - Enc_sender(value).cl - Enc_sender(fee).cl
        //  == (remaining_balance)G + decryption_key * (Enc_sender(sender_balance).cr - (random)G - (random)G)
        // <==> Enc_sender(sender_balance).cl + decryption_key * (random)G + decryption_key * (random)G
        //       == (remaining_balance)G + decryption_key * Enc_sender(sender_balance).cr + Enc_sender(value).cl + Enc_sender(fee).cl
        {
            let bal_gl = ecc::EdwardsPoint::witness(
                cs.namespace(|| "balance left"),
                self.encrypted_balance.as_ref().map(|e| e.left.clone()),
                params
            )?;

            bal_gl.assert_not_small_order(
                cs.namespace(|| "bal_gl not small order"),
                params
            )?;

            let bal_gr = ecc::EdwardsPoint::witness(
                cs.namespace(|| "balance right"),
                self.encrypted_balance.as_ref().map(|e| e.right.clone()),
                params
            )?;

            bal_gr.assert_not_small_order(
                cs.namespace(|| "bal_gr not small order"),
                params
            )?;

            let left = self.encrypted_balance.clone().map(|e| e.left.into_xy());
            let right = self.encrypted_balance.map(|e| e.right.into_xy());

            let numxl = AllocatedNum::alloc(cs.namespace(|| "numxl"), || {
                Ok(left.get()?.0)
            })?;
            let numyl = AllocatedNum::alloc(cs.namespace(|| "numyl"), || {
                Ok(left.get()?.1)
            })?;
            let numxr = AllocatedNum::alloc(cs.namespace(|| "numxr"), || {
                Ok(right.get()?.0)
            })?;
            let numyr = AllocatedNum::alloc(cs.namespace(|| "numyr"), || {
                Ok(right.get()?.1)
            })?;

            let pointl = EdwardsPoint::interpret(
                cs.namespace(|| format!("interpret to pointl")),
                &numxl,
                &numyl,
                params
            )?;

            let pointr = EdwardsPoint::interpret(
                cs.namespace(|| format!("interpret to pointr")),
                &numxr,
                &numyr,
                params
            )?;

            //  decryption_key * (random)G
            let decryption_key_random = c_right.mul(
                cs.namespace(|| format!("c_right mul by decryption_key")),
                &decryption_key_v,
                params
                )?;

            // Enc_sender(sender_balance).cl + decryption_key * (random)G
            let senderbalance_decryption_key_random = pointl.add(
                cs.namespace(|| format!("pointl add decryption_key_pointl")),
                &decryption_key_random,
                params
                )?;

            // Enc_sender(sender_balance).cl + decryption_key * (random)G + decryption_key * (random)G
            let bi_left = senderbalance_decryption_key_random.add(
                cs.namespace(|| format!("pointl readd decryption_key_pointl")),
                &decryption_key_random,
                params
                )?;

            // decryption_key * Enc_sender(sender_balance).cr
            let decryption_key_pointr = pointr.mul(
                cs.namespace(|| format!("c_right_sender mul by decryption_key")),
                &decryption_key_v,
                params
                )?;

            // Compute (remaining_balance)G
            let rem_bal_g = ecc::fixed_base_multiplication(
                cs.namespace(|| format!("compute the remaining balance in the exponent")),
                FixedGenerators::NoteCommitmentRandomness,
                &rem_bal_bits,
                params
                )?;

            // Enc_sender(value).cl + (remaining_balance)G
            let val_rem_bal = c_left_sender.add(
                cs.namespace(|| format!("c_left_sender add rem_bal_g")),
                &rem_bal_g,
                params
                )?;

            // Enc_sender(value).cl + (remaining_balance)G + decryption_key * Enc_sender(sender_balance).cr
            let val_rem_bal_balr = val_rem_bal.add(
                cs.namespace(|| format!("val_rem_bal add ")),
                &decryption_key_pointr,
                params
                )?;

            // Enc_sender(value).cl + (remaining_balance)G + decryption_key * Enc_sender(sender_balance).cr + Enc_sender(fee).cl
            let bi_right = f_left_sender.add(
                cs.namespace(|| format!("f_left_sender add")),
                &val_rem_bal_balr,
                params
            )?;

            // The left hand for balance integrity into representation
            let bi_left_repr = bi_left.repr(
                cs.namespace(|| format!("bi_left into a representation"))
            )?;

            // The right hand for balance integrity into representation
            let bi_right_repr = bi_right.repr(
                cs.namespace(|| format!("bi_right into a representation"))
            )?;

            let iter = bi_left_repr.iter().zip(bi_right_repr.iter());

            // Ensure for the sender's balance integrity
            for (i, (a, b)) in iter.enumerate() {
                Boolean::enforce_equal(
                    cs.namespace(|| format!("bi_left equals bi_right {}", i)),
                    &a,
                    &b
                )?;
            }

            pointl.inputize(cs.namespace(|| format!("inputize pointl")))?;
            pointr.inputize(cs.namespace(|| format!("inputize pointr")))?;
        }


        // Ensure pgk on the curve.
        let pgk = ecc::EdwardsPoint::witness(
            cs.namespace(|| "pgk"),
            self.proof_generation_key.as_ref().map(|k| k.0.clone()),
            self.params
        )?;

        // Ensure pgk is large order.
        pgk.assert_not_small_order(
            cs.namespace(|| "pgk not small order"),
            self.params
        )?;

        // Re-randomized parameter for pgk
        let alpha = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "alpha"),
            self.alpha
        )?;

        // Make the alpha on the curve
        let alpha_g = ecc::fixed_base_multiplication(
            cs.namespace(|| "computation of randomiation for the signing key"),
            FixedGenerators::NoteCommitmentRandomness,
            &alpha,
            self.params
        )?;

        // Ensure randomaized sig-verification key is computed by the addition of ak and alpha_g
        let rvk = pgk.add(
            cs.namespace(|| "computation of rvk"),
            &alpha_g,
            self.params
        )?;

        // Ensure rvk is large order.
        rvk.assert_not_small_order(
            cs.namespace(|| "rvk not small order"),
            self.params
        )?;

        rvk.inputize(cs.namespace(|| "rvk"))?;

        Ok(())
    }
}

fn u32_into_boolean_vec_le<E, CS>(
    mut cs: CS,
    value: Option<u32>
) -> Result<Vec<Boolean>, SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{
    let values = match value {
        Some(ref value) => {
            let mut tmp = Vec::with_capacity(32);
            for i in 0..32 {
                tmp.push(Some(*value >> i & 1 == 1));
            }
            tmp
        },

        None => {
            vec![None; 32]
        }
    };

    let bits = values.into_iter()
            .enumerate()
            .map(|(i, v)| {
                Ok(boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    v
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::{bls12_381::{Bls12, Fr}, Field};
    use rand::{SeedableRng, Rng, XorShiftRng, Rand};
    use crate::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards, JubjubParams};
    use crate::primitives::EncryptionKey;

    #[test]
    fn test_circuit_transfer() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let sk_fs_s: fs::Fs = rng.gen();
        let sk_fs_r: fs::Fs = rng.gen();

        let proof_generation_key_s = ProofGenerationKey::<Bls12>::from_origin_key(&sk_fs_s, params);
        let proof_generation_key_r = ProofGenerationKey::<Bls12>::from_origin_key(&sk_fs_r, params);

        let decryption_key_s: fs::Fs = proof_generation_key_s.bdk();
        let decryption_key_r: fs::Fs = proof_generation_key_r.bdk();

        let address_recipient = EncryptionKey::from_origin_key(&sk_fs_r, params);
        let address_sender_xy = proof_generation_key_s.into_encryption_key(params).0.into_xy();
        let address_recipient_xy = address_recipient.0.into_xy();

        let alpha: fs::Fs = rng.gen();

        let value = 10 as u32;
        let remaining_balance = 17 as u32;
        let current_balance = 27 as u32;
        let fee = 1 as u32;

        let r_fs_b = fs::Fs::rand(rng);
        let r_fs_v = fs::Fs::rand(rng);

        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let public_key_s = params.generator(p_g).mul(decryption_key_s, params).into();
        let ciphetext_balance = Ciphertext::encrypt(current_balance, r_fs_b, &public_key_s, p_g, params);

        let c_bal_left = ciphetext_balance.left.into_xy();
        let c_bal_right = ciphetext_balance.right.into_xy();

        let ciphertext_value_sender = Ciphertext::encrypt(value, r_fs_v, &public_key_s, p_g, params);
        let c_val_s_left = ciphertext_value_sender.left.into_xy();
        let c_val_right = ciphertext_value_sender.right.into_xy();

        let ciphertext_fee_sender = Ciphertext::encrypt(fee, r_fs_v, &public_key_s, p_g, params);
        let c_fee_s_left = ciphertext_fee_sender.left.into_xy();
        let c_fee_s_right = ciphertext_fee_sender.right.into_xy();

        let public_key_r = params.generator(p_g).mul(decryption_key_r, params).into();
        let ciphertext_value_recipient = Ciphertext::encrypt(value, r_fs_v, &public_key_r, p_g, params);
        let c_val_r_left = ciphertext_value_recipient.left.into_xy();

        let rvk = proof_generation_key_s.rvk(alpha, params).into_xy();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Transfer {
            params: params,
            value: Some(value),
            remaining_balance: Some(remaining_balance),
            randomness: Some(r_fs_v.clone()),
            alpha: Some(alpha.clone()),
            proof_generation_key: Some(proof_generation_key_s.clone()),
            decryption_key: Some(decryption_key_s.clone()),
            pk_d_recipient: Some(address_recipient.0.clone()),
            encrypted_balance: Some(ciphetext_balance.clone()),
            fee: Some(fee),
        };

        instance.synthesize(&mut cs).unwrap();

        assert!(cs.is_satisfied()); // TODO: failed here!
        // assert_eq!(cs.num_constraints(), 18278);
        // assert_eq!(cs.hash(), "6858d345922e8a5f173dafb61264ea237b9f0fad75f51c656461cd43fdd3db34");

        assert_eq!(cs.num_inputs(), 19);
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(cs.get_input(1, "inputize pk_d_sender/x/input variable"), address_sender_xy.0);
        assert_eq!(cs.get_input(2, "inputize pk_d_sender/y/input variable"), address_sender_xy.1);
        assert_eq!(cs.get_input(3, "inputize pk_d_recipient/x/input variable"), address_recipient_xy.0);
        assert_eq!(cs.get_input(4, "inputize pk_d_recipient/y/input variable"), address_recipient_xy.1);
        assert_eq!(cs.get_input(5, "c_left_sender/x/input variable"), c_val_s_left.0);
        assert_eq!(cs.get_input(6, "c_left_sender/y/input variable"), c_val_s_left.1);
        assert_eq!(cs.get_input(7, "c_left_recipient/x/input variable"), c_val_r_left.0);
        assert_eq!(cs.get_input(8, "c_left_recipient/y/input variable"), c_val_r_left.1);
        assert_eq!(cs.get_input(9, "c_right/x/input variable"), c_val_right.0);
        assert_eq!(cs.get_input(10, "c_right/y/input variable"), c_val_right.1);
        assert_eq!(cs.get_input(11, "f_left_sender/x/input variable"), c_fee_s_left.0);
        assert_eq!(cs.get_input(12, "f_left_sender/y/input variable"), c_fee_s_left.1);
        assert_eq!(cs.get_input(13, "inputize pointl/x/input variable"), c_bal_left.0);
        assert_eq!(cs.get_input(14, "inputize pointl/y/input variable"), c_bal_left.1);
        assert_eq!(cs.get_input(15, "inputize pointr/x/input variable"), c_bal_right.0);
        assert_eq!(cs.get_input(16, "inputize pointr/y/input variable"), c_bal_right.1);
        assert_eq!(cs.get_input(17, "rvk/x/input variable"), rvk.0);
        assert_eq!(cs.get_input(18, "rvk/y/input variable"), rvk.1);
    }
}
