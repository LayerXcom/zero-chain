use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,    
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};

use scrypto::jubjub::{
    JubjubEngine,
    FixedGenerators
};

use scrypto::constants;

use scrypto::primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress
};

use scrypto::circuit::{    
    boolean,
    ecc,
    pedersen_hash,
    blake2s,
    num,
    multipack
};

// An instance of the Transfer circuit.
pub struct Transfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,     
    pub transfer_value_commitment: Option<ValueCommitment<E>>,
    pub balance_value_commitment: Option<ValueCommitment<E>>,            
    // Re-randomization of the public key
    pub ar: Option<E::Fs>,
    pub proof_generation_key: Option<ProofGenerationKey<E>>, // ak and nsk
    pub esk: Option<E::Fs>,
    // The payment address associated with the note
    pub prover_payment_address: Option<PaymentAddress<E>>,
    // The payment address  of the recipient
    pub recipient_payment_address: Option<PaymentAddress<E>>,
}

// pub struct Transfer<'a, E: JubjubEngine> {
//     pub params: &'a E::Params, 
//     pub proof_generation_key: Option<ProofGenerationKey<E>>,
//     // The payment address associated with the note
//     pub prover_payment_address: Option<PaymentAddress<E>>,
//     // The payment address  of the recipient
//     pub recipient_payment_address: Option<PaymentAddress<E>>,
//     pub old_value: Option<u64>, 
//     pub prover_value: Option<u64>,
//     pub recipient_value: Option<u64>,
//     pub esk: Option<E::Fs>,
//     // Re-randomization of the public key
//     pub ar: Option<E::Fs>,
// }



fn expose_value_commitment<E, CS>(
    mut cs: CS,
    value_commitment: &Option<ValueCommitment<E>>,
    transfer_or_balance: &str,
    params: &E::Params
) -> Result<(), SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| format!("{} value", transfer_or_balance)), 
        value_commitment.as_ref().map(|c| c.value)
    )?;

    let value = ecc::fixed_base_multiplication(
        cs.namespace(|| format!("compute the {} value in the exponent", transfer_or_balance)), 
        FixedGenerators::ValueCommitmentValue, 
        &value_bits, 
        params
    )?;

    let rcv = boolean::field_into_boolean_vec_le(
        cs.namespace(|| format!("{} rcv", transfer_or_balance)), 
        value_commitment.as_ref().map(|c| c.randomness)
    )?;

    let rcv = ecc::fixed_base_multiplication(
        cs.namespace(|| format!("computation of {} rcv", transfer_or_balance)), 
        FixedGenerators::ValueCommitmentRandomness, 
        &rcv, 
        params
    )?;

    let cv = value.add(
        cs.namespace(|| format!("computation of {} cv", transfer_or_balance)),
        &rcv,
        params
    )?;

    cv.inputize(cs.namespace(|| format!("{} commitment point", transfer_or_balance)))?;  
    Ok(())  
}

fn u64_into_alloc<E, CS>(
    mut cs: CS,
    value: Option<u64>
) -> Result<(), SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{
    let values = match value {
        Some(ref value) => {
            let mut tmp = Vec::with_capacity(64);
            for i in 0..64 {
                tmp.push(Some(*value >> i & 1 == 1));
            }
            tmp
        },

        None => {
            vec![None; 64]
        }
    };

    let _bits = values.into_iter()
            .enumerate()
            .map(|(i, v)| {
                Ok(boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    v
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
    
    Ok(())
}

impl<'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {        
        // todo expose payment_address

        // value commitment integrity of sender's balance and expose the commitment publicly.   
        expose_value_commitment(
            cs.namespace(|| "balance commitment"), 
            &self.balance_value_commitment, 
            "balance", 
            self.params
        )?;        

        // value commitment integrity of transferring amount and expose the commitment publicly.        
        expose_value_commitment(
            cs.namespace(|| "transfer commitment"), 
            &self.transfer_value_commitment, 
            "transfer", 
            self.params
        )?;

        // Ensure transferring amount is not over the sender's balance
        self.balance_value_commitment.as_ref().map(|b|
            self.transfer_value_commitment.as_ref().map(|t|
                u64_into_alloc(
                    cs.namespace(|| "range proof of balance"), 
                    Some(b.value - t.value))
            )
        ).unwrap();        

        // Prover witnesses recipient_g_d, ensuring it's on the curve.
        let recipient_g_d = ecc::EdwardsPoint::witness(
            cs.namespace(|| "witness recipient_g_d"),
            self.recipient_payment_address.as_ref().and_then(|a| a.g_d(self.params)),
            self.params
        )?;

        // Ensure recipient_g_d is large order.
        recipient_g_d.assert_not_small_order(
            cs.namespace(|| "recipient_g_d not small order"),
            self.params
        )?;
        
        let esk = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "esk"),
            self.esk
        )?;

        // Create the ephemeral public key from recipient_g_d.
        let epk = recipient_g_d.mul(
            cs.namespace(|| "epk computation"),
            &esk,
            self.params
        )?;

        // Expose epk publicly.
        epk.inputize(cs.namespace(|| "epk"))?;

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
        {
            let ar = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "ar"),
                self.ar
            )?;

            let ar = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of randomiation for the signing key"),
                FixedGenerators::SpendingKeyGenerator,
                &ar,
                self.params
            )?;

            let rk = ak.add(
                cs.namespace(|| "computation of rk"),
                &ar,
                self.params
            )?;

            rk.inputize(cs.namespace(|| "rk"))?;
        }
        
        // Compute proof generation key
        let nk;
        {
            let nsk = boolean::field_into_boolean_vec_le(
                cs.namespace(|| "nsk"),
                self.proof_generation_key.as_ref().map(|k| k.nsk.clone())
            )?;

            nk = ecc::fixed_base_multiplication(
                cs.namespace(|| "computation of nk"),
                FixedGenerators::ProofGenerationKey,
                &nsk,
                self.params
            )?;
        }

        let mut ivk_preimage = vec![];
        ivk_preimage.extend(
            ak.repr(cs.namespace(|| "representation of ak"))?
        );
        
        ivk_preimage.extend(
            nk.repr(cs.namespace(|| "representation of nk"))?
        );
        
        assert_eq!(ivk_preimage.len(), 512);
    
        let mut ivk = blake2s::blake2s(
            cs.namespace(|| "computation of ivk"),
            &ivk_preimage,
            constants::CRH_IVK_PERSONALIZATION
        )?;

        ivk.truncate(E::Fs::CAPACITY as usize);

        // Ensure prover_g_d on the curve.
        let prover_g_d = {
            let params = self.params;
            ecc::EdwardsPoint::witness(
                cs.namespace(|| "witness prover_g_d"),
                self.prover_payment_address.as_ref().and_then(|a| a.g_d(params)),
                self.params
            )?
        };   

        prover_g_d.assert_not_small_order(
            cs.namespace(|| "prover_g_d not small order"),
            self.params
        )?;

        let prover_pk_d = prover_g_d.mul(
            cs.namespace(|| "compute prover_pk_d"),
            &ivk,
            self.params
        )?;

        Ok(())        
    }
}

#[cfg(test)]
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};    
    use super::test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards};
    use scrypto::primitives::Diversifier;

    
    #[test]
    fn test_transfer_circuit() {        
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let nsk: fs::Fs = rng.gen();
        let ak = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proof_generation_key = ProofGenerationKey {
            ak: ak.clone(),
            nsk: nsk.clone()
        };

        let viewing_key = proof_generation_key.into_viewing_key(params);
        let prover_payment_address;

        loop {
            let diversifier = Diversifier(rng.gen());

            if let Some(p) = viewing_key.into_payment_address(
                diversifier, 
                params
            )
            {
                prover_payment_address = p;
                break;
            }
        }

        let recipient_payment_address;        
        let nsk_r: fs::Fs = rng.gen();
        let ak_r = edwards::Point::rand(rng, params).mul_by_cofactor(params);

        let proof_generation_key_r = ProofGenerationKey {
            ak: ak_r.clone(),
            nsk: nsk_r.clone()
        };

        let viewing_key_r = proof_generation_key_r.into_viewing_key(params);
        loop {
            let diversifier_r = Diversifier(rng.gen());

            if let Some(p) = viewing_key_r.into_payment_address(
                diversifier_r, 
                params
            )
            {
                recipient_payment_address = p;
                break;
            }
        }                        

        let esk: fs::Fs = rng.gen();
        let ar: fs::Fs = rng.gen();

        let transfer_value_commitment = ValueCommitment {
            value: rng.gen(),
            randomness: rng.gen()
        };

        let balance_value_commitment = ValueCommitment {
            value: transfer_value_commitment.value + (5 as u64), 
            randomness: rng.gen()
        };

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Transfer {
            params: params,
            transfer_value_commitment: Some(transfer_value_commitment.clone()),
            balance_value_commitment: Some(balance_value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            prover_payment_address: Some(prover_payment_address.clone()),
            recipient_payment_address: Some(recipient_payment_address.clone()),                                
            esk: Some(esk.clone()),
            ar: Some(ar)
        };        

        instance.synthesize(&mut cs).unwrap();

        // let expected_epk
        // let expected_epk_xy
        
        println!("transfer_constraints: {:?}", cs.num_constraints());
        assert!(cs.is_satisfied());
        // assert_eq!(cs.num_constraints(), 75415);
        // assert_eq!(cs.hash(), "3ff9338cc95b878a20b0974490633219e032003ced1d3d917cde4f50bc902a12");
        
        println!("num_inputs: {:?}", cs.num_inputs());
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
    }

