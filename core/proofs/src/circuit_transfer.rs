use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};

use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators,
    PrimeOrder,    
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
    pub ivk: Option<E::Fs>, 
    pub pk_d_recipient: Option<edwards::Point<E, PrimeOrder>>,
    pub encrypted_balance: Option<Ciphertext<E>>,
}

impl<'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>    
    { 
        let params = self.params;

        // Ensure the value is u32.        
        u32_into_boolean_vec_le(
            cs.namespace(|| "range proof of value"), 
            self.value
        )?;

        // Ensure the remaining balance is u32.
        u32_into_boolean_vec_le(
            cs.namespace(|| "range proof of remaining_balance"), 
            self.remaining_balance
        )?;            

        // ivk in circuit
        let ivk_v = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("ivk")),
            self.ivk 
        )?;

        // Ensure the validity of pk_d_sender
        let pk_d_sender_v = ecc::fixed_base_multiplication(
            cs.namespace(|| "compute pk_d_sender"),
            FixedGenerators::NoteCommitmentRandomness,
            &ivk_v,
            params
        )?;        

        // Expose the pk_d_sender publicly
        pk_d_sender_v.inputize(cs.namespace(|| format!("inputize pk_d_sender")))?;        


        // Generate the amount into the circuit
        let value_bits = u32_into_boolean_vec_le(
            cs.namespace(|| format!("value bits")), 
            self.value
        )?;

        // Multiply the value to the base point same as FixedGenerators::ElGamal.
        let value_g = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the value in the exponent")), 
            FixedGenerators::NoteCommitmentRandomness, 
            &value_bits, 
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
        
        val_rlr.inputize(cs.namespace(|| format!("inputize pk_d_recipient")))?; 


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
    
        // Expose the ciphertext publicly.
        c_left_sender.inputize(cs.namespace(|| format!("c_left_sender")))?;
        c_left_recipient.inputize(cs.namespace(|| format!("c_left_recipient")))?;
        c_right.inputize(cs.namespace(|| format!("c_right")))?;

        
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

            pointl.inputize(cs.namespace(|| format!("inputize pointl")))?;
            pointr.inputize(cs.namespace(|| format!("inputize pointr")))?;

            // TODO:
            // The balance encryption validity. 
            // It is a bit complicated bacause we can not know the randomness of balance.
            // { (current_balance)G - (value)G } + (rbar - random)pk_d_sender  
            //   == (remaining_balance)G + (ivk){ (rbar)G - (random)G }
            // rbar is the current_balance randomness   
            // Enc_sender(sender_balance).cl - Enc_sender(value).cl 
            //     == (remaining_balance)G + ivk(Enc_sender(sender_balance).cr - Enc(random))
        }


        // Ensure ak on the curve.
        let ak = ecc::EdwardsPoint::witness(
            cs.namespace(|| "ak"),
            self.proof_generation_key.as_ref().map(|k| k.ak.clone()),
            self.params
        )?;

        // Ensure ak is large order.
        ak.assert_not_small_order(
            cs.namespace(|| "ak not small order"),
            self.params
        )?;

        // Re-randomize ak    
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

        // Ensure re-randomaized sig-verification key is computed by the addition of ak and alpha_g
        let rk = ak.add(
            cs.namespace(|| "computation of rk"),
            &alpha_g,
            self.params
        )?;

        // Ensure rk is large order.
        rk.assert_not_small_order(
            cs.namespace(|| "rk not small order"),
            self.params
        )?;

        rk.inputize(cs.namespace(|| "rk"))?;                                          

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
    use pairing::{PrimeField, bls12_381::*};
    use rand::{SeedableRng, Rng, XorShiftRng};    
    use super::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards, JubjubParams, ToUniform};  
    use crate::elgamal::elgamal_extend;         

    
    #[test]
    fn test_circuit_transfer() {        
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);        

        let nsk_s: fs::Fs = rng.gen();
        let ak_s = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proof_generation_key_s = ProofGenerationKey {
            ak: ak_s.clone(),
            nsk: nsk_s.clone()
        };

        let viewing_key_s = proof_generation_key_s.into_viewing_key(params);
        let ivk_s: fs::Fs = viewing_key_s.ivk();
                     
        let nsk_r: fs::Fs = rng.gen();
        
        let ak_r = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proof_generation_key_r = ProofGenerationKey {
            ak: ak_r.clone(),
            nsk: nsk_r.clone()
        };

        let viewing_key_r = proof_generation_key_r.into_viewing_key(params);
        let address_recipient = viewing_key_r.into_payment_address(params);                          
        
        let ar: fs::Fs = rng.gen();

        let value = 10 as u32;
        let remaining_balance = 17 as u32;
        let current_balance = 27 as u32;

        let mut randomness = [0u8; 32];
        rng.fill_bytes(&mut randomness[..]);
        let r_fs = fs::Fs::to_uniform(elgamal_extend(&randomness).as_bytes());

        let p_g = FixedGenerators::NoteCommitmentRandomness;
        let public_key = params.generator(p_g).mul(r_fs, params).into();
        let ciphetext = Ciphertext::encrypt(current_balance, r_fs, &public_key, p_g, params);

        let rk = viewing_key_s.rk(ar, params).into_xy();
        let randomness: fs::Fs = rng.gen();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Transfer {
            params: params,
            value: Some(value),
            remaining_balance: Some(remaining_balance),
            randomness: Some(randomness.clone()),
            alpha: Some(ar.clone()),
            proof_generation_key: Some(proof_generation_key_s.clone()),
            ivk: Some(ivk_s.clone()),
            pk_d_recipient: Some(address_recipient.0.clone()),
            encrypted_balance: Some(ciphetext.clone())            
        };        

        instance.synthesize(&mut cs).unwrap();        
        
        println!("transfer_constraints: {:?}", cs.num_constraints());
        assert!(cs.is_satisfied());
        // assert_eq!(cs.num_constraints(), 75415);
        // assert_eq!(cs.hash(), "3ff9338cc95b878a20b0974490633219e032003ced1d3d917cde4f50bc902a12");
        
        // assert_eq!(cs.num_inputs(), 7);
        // assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        // assert_eq!(cs.get_input(1, "balance commitment/balance commitment point/x/input variable"), expected_balance_cm.0);
        // assert_eq!(cs.get_input(2, "balance commitment/balance commitment point/y/input variable"), expected_balance_cm.1);
        // assert_eq!(cs.get_input(3, "transfer commitment/transfer commitment point/x/input variable"), expected_transfer_cm.0);
        // assert_eq!(cs.get_input(4, "transfer commitment/transfer commitment point/y/input variable"), expected_transfer_cm.1);        
        // assert_eq!(cs.get_input(5, "rk/x/input variable"), rk.0);
        // assert_eq!(cs.get_input(6, "rk/y/input variable"), rk.1);        
    }
