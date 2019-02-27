use pairing::{
    PrimeField,    
};

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

use zcrypto::constants;

use crate::primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress,        
};

use scrypto::circuit::{    
    boolean,
    ecc,    
    blake2s,    
};

// An instance of the Transfer circuit.
pub struct Transfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,    
    pub value: Option<u32>,
    pub value_random: Option<E::Fs>,    
    pub balance: Option<u32>,       
    pub balance_random: Option<E::Fs>,    
    // Re-randomization of the public key
    pub ar: Option<E::Fs>,
    pub proof_generation_key: Option<ProofGenerationKey<E>>, // ak and nsk    
    // The payment address associated with the note
    pub address_sender: Option<PaymentAddress<E>>,        
}

fn expose_ciphertext<E, CS>(
    mut cs: CS,
    amount: Option<u32>,
    randomness: Option<E::Fs>,
    pk_d: Option<edwards::Point<E, PrimeOrder>>,
    value_or_balance: &str,
    params: &E::Params
) -> Result<(), SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{
    let value_bits = boolean::u32_into_boolean_vec_le(
        cs.namespace(|| format!("{} value", value_or_balance)), 
        amount
    )?;

    let value = ecc::fixed_base_multiplication(
        cs.namespace(|| format!("compute the {} value in the exponent", value_or_balance)), 
        FixedGenerators::ElGamal, 
        &value_bits, 
        params
    )?;

    let rcv = boolean::field_into_boolean_vec_le(
        cs.namespace(|| format!("{} rcv", value_or_balance)), 
        randomness
    )?;

    let rcv = ecc::fixed_base_multiplication(
        cs.namespace(|| format!("computation of {} rcv", value_or_balance)), 
        FixedGenerators::ElGamal, 
        &rcv, 
        params
    )?;

    // TODO:
    // let rsp = ecc::mul(
    //     cs.namespace(|| format!("{} rsp", value_or_balance)),
    //     edwards::Point,
    //     &rcv,
    //     params
    // )
    
    let cv = value.add(
        cs.namespace(|| format!("computation of {} cv", value_or_balance)),
        &rcv, // TODO: Replace with &rsp
        params
    )?;
    
    cv.inputize(cs.namespace(|| format!("{} sbar point", value_or_balance)))?;  
    rcv.inputize(cs.namespace(|| format!("{} tbar point ", value_or_balance)))?;
    Ok(())  
}

fn u32_into_boolean_vec_le<E, CS>(
    mut cs: CS,
    value: Option<u32>
) -> Result<(), SynthesisError>
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
        // value ciphertext integrity of sender's balance and expose the ciphertext publicly.   
        expose_ciphertext(
            cs.namespace(|| "balance ciphertext"), 
            balance,
            balance_random,
            public,
            "balance", 
            self.params
        )?;        

        // value ciphertext integrity of transferring amount and expose the ciphertext publicly.        
        expose_ciphertext(
            cs.namespace(|| "value ciphertext"), 
            &self.transfer_value_commitment, 
            "value", 
            self.params
        )?;

        // Ensure transferring value is not over the sender's balance
        self.balance.as_ref().map(|b|
            self.value.as_ref().map(|v|
                u32_into_boolean_vec_le(
                    cs.namespace(|| "range proof of balance"), 
                    Some(b - v))
            )
        ).unwrap();        

        // // Prover witnesses recipient_g_d, ensuring it's on the curve.
        // let recipient_g_d = ecc::EdwardsPoint::witness(
        //     cs.namespace(|| "witness recipient_g_d"),
        //     self.address_recipient.as_ref().and_then(|a| a.g_d(self.params)),
        //     self.params
        // )?;

        // // Ensure recipient_g_d is large order.
        // recipient_g_d.assert_not_small_order(
        //     cs.namespace(|| "recipient_g_d not small order"),
        //     self.params
        // )?;                        

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
                self.address_sender.as_ref().and_then(|a| a.g_d(params)),
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
    use super::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards};
    use crate::primitives::Diversifier;
    use pairing::Field;

    
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
        let address_sender;

        loop {
            let diversifier_s = Diversifier(rng.gen());

            if let Some(p) = viewing_key_s.into_payment_address(
                diversifier_s, 
                params
            )
            {
                address_sender = p;
                break;
            }
        }

        let address_recipient;        
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
                address_recipient = p;
                break;
            }
        }                        
        
        let ar: fs::Fs = rng.gen();

        let transfer_value_commitment = ValueCommitment {
            value: rng.gen(),
            randomness: rng.gen(),
            is_negative: false,
        };

        let balance_value_commitment = ValueCommitment {
            value: transfer_value_commitment.value + (5 as u64), 
            randomness: rng.gen(),
            is_negative: false,
        };

        let expected_balance_cm = balance_value_commitment.cm(params).into_xy();
        let expected_transfer_cm = transfer_value_commitment.cm(params).into_xy();

        let rk = viewing_key_s.rk(ar, params).into_xy();

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = Transfer {
            params: params,
            transfer_value_commitment: Some(transfer_value_commitment.clone()),
            balance_value_commitment: Some(balance_value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key_s.clone()),
            address_sender: Some(address_sender.clone()),
            address_recipient: Some(address_recipient.clone()),                                            
            ar: Some(ar.clone())
        };        

        instance.synthesize(&mut cs).unwrap();        
        
        println!("transfer_constraints: {:?}", cs.num_constraints());
        assert!(cs.is_satisfied());
        // assert_eq!(cs.num_constraints(), 75415);
        // assert_eq!(cs.hash(), "3ff9338cc95b878a20b0974490633219e032003ced1d3d917cde4f50bc902a12");
        
        assert_eq!(cs.num_inputs(), 7);
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        assert_eq!(cs.get_input(1, "balance commitment/balance commitment point/x/input variable"), expected_balance_cm.0);
        assert_eq!(cs.get_input(2, "balance commitment/balance commitment point/y/input variable"), expected_balance_cm.1);
        assert_eq!(cs.get_input(3, "transfer commitment/transfer commitment point/x/input variable"), expected_transfer_cm.0);
        assert_eq!(cs.get_input(4, "transfer commitment/transfer commitment point/y/input variable"), expected_transfer_cm.1);        
        assert_eq!(cs.get_input(5, "rk/x/input variable"), rk.0);
        assert_eq!(cs.get_input(6, "rk/y/input variable"), rk.1);        
    }
