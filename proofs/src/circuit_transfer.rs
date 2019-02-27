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
    JubjubParams,
};

use zcrypto::{constants, elgamal::Ciphertext};

use crate::primitives::{
    ValueCommitment,
    ProofGenerationKey,
    PaymentAddress,        
};

use scrypto::circuit::{    
    boolean::{self, Boolean},
    ecc::{self, EdwardsPoint},    
    blake2s,    
    num::{AllocatedNum, Num},
};
// From no_std
use zpairing::bls12_381::Bls12;

// An instance of the Transfer circuit.
pub struct Transfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params,    
    pub value: Option<u32>,    
    pub remaining_balance: Option<u32>,       
    pub randomness: Option<E::Fs>,        
    pub alpha: Option<E::Fs>,
    pub proof_generation_key: Option<ProofGenerationKey<E>>, // ak and nsk        
    pub ivk: Option<E::Fs>,    
    pub pk_d_recipient: Option<edwards::Point<E, PrimeOrder>>,
    pub encrypted_balance: Option<Ciphertext<Bls12>>,
}

fn get_rsg<E, CS>(
    mut cs: CS,    
    rcv: &[Boolean],
    pk_d: Option<edwards::Point<E, PrimeOrder>>,
    address: &str,
    params: &E::Params
) -> Result<EdwardsPoint<E>, SynthesisError>
    where E: JubjubEngine, CS: ConstraintSystem<E>
{    
    let (x, y) = pk_d.map(|e| e.into_xy()).unwrap();    

    let numx = AllocatedNum::alloc(cs.namespace(|| "mont x"), || {
        Ok(x)
    })?;
    let numy = AllocatedNum::alloc(cs.namespace(|| "mont y"), || {
        Ok(y)
    })?;

    // Generate the point into the circuit
    let point = EdwardsPoint::interpret(
        cs.namespace(|| format!("{} interpret to the point", address)),
        &numx, 
        &numy, 
        params
    )?;      

    let rsg = point.mul(
        cs.namespace(|| format!("{} rsg", address)), 
        rcv, 
        params
    )?;   

    Ok(rsg)
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

impl<'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>    
    { 
        let params = self.params;

        // Ensure the value is u32.
        self.value.map(|v|
            u32_into_boolean_vec_le(
                cs.namespace(|| "range proof of value"), 
                Some(v)
            )
        ).unwrap();
        
        // Ensure the remaining balance is u32.
        self.remaining_balance.map(|b|
            u32_into_boolean_vec_le(
                cs.namespace(|| "range proof of remaining balance"), 
                Some(b)
            )
        ).unwrap();    

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
            FixedGenerators::NullifierPosition, 
            &value_bits, 
            params
        )?;

        // Generate the randomness into the circuit
        let rcv = boolean::field_into_boolean_vec_le(
            cs.namespace(|| format!("rcv")), 
            self.randomness
        )?; 

        let p_g = FixedGenerators::NoteCommitmentRandomness;

        let pk_d_sender = params
            .generator(p_g)
            .mul(self.ivk.unwrap(), params);

        // Generate the randomness * pk_d_sender in circuit
        let rsg_sender = get_rsg(
            cs.namespace(|| format!("get sender's rsg")),
            &rcv,
            Some(pk_d_sender), 
            "sender", 
            params
        )?;

        // Generate the randomness * pk_d_recipient in circuit
        let rsg_recipient = get_rsg(
            cs.namespace(|| format!("get recipient's rsg")),
            &rcv,
            self.pk_d_recipient, 
            "recipient", 
            params
        )?;

        rsg_recipient.inputize(cs.namespace(|| format!("inputize pk_d_recipient")))?; 

        // Generate the left elgamal component for sender in circuit
        let c_left_sender = value_g.add(
            cs.namespace(|| format!("computation of sender's c_left")),
            &rsg_sender, 
            params
        )?;

        // Generate the left elgamal component for recipient in circuit
        let c_left_recipient = value_g.add(
            cs.namespace(|| format!("computation of recipient's c_left")),
            &rsg_recipient, 
            params
        )?;        

        // Multiply the randomness to the base point same as FixedGenerators::ElGamal.
        let c_right = ecc::fixed_base_multiplication(
            cs.namespace(|| format!("compute the right elgamal component")), 
            FixedGenerators::NullifierPosition, 
            &rcv, 
            params
        )?;
    
        // Expose the ciphertext publicly.
        c_left_sender.inputize(cs.namespace(|| format!("c_left_sender")))?;
        c_left_recipient.inputize(cs.namespace(|| format!("c_left_recipient")))?;
        c_right.inputize(cs.namespace(|| format!("c_right")))?;

        // TODO:
        

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

        let alpha = ecc::fixed_base_multiplication(
            cs.namespace(|| "computation of randomiation for the signing key"),
            FixedGenerators::SpendingKeyGenerator,
            &alpha,
            self.params
        )?;

        let rk = ak.add(
            cs.namespace(|| "computation of rk"),
            &alpha,
            self.params
        )?;

        // Ensure rk is large order.
        rk.assert_not_small_order(
            cs.namespace(|| "rk not small order"),
            self.params
        )?;

        rk.inputize(cs.namespace(|| "rk"))?;        
        
        // // Compute proof generation key
        // let nk;
        // {
        //     let nsk = boolean::field_into_boolean_vec_le(
        //         cs.namespace(|| "nsk"),
        //         self.proof_generation_key.as_ref().map(|k| k.nsk.clone())
        //     )?;

        //     nk = ecc::fixed_base_multiplication(
        //         cs.namespace(|| "computation of nk"),
        //         FixedGenerators::ProofGenerationKey,
        //         &nsk,
        //         self.params
        //     )?;
        // }

        // let mut ivk_preimage = vec![];
        // ivk_preimage.extend(
        //     ak.repr(cs.namespace(|| "representation of ak"))?
        // );
        
        // ivk_preimage.extend(
        //     nk.repr(cs.namespace(|| "representation of nk"))?
        // );
        
        // assert_eq!(ivk_preimage.len(), 512);
    
        // let mut ivk = blake2s::blake2s(
        //     cs.namespace(|| "computation of ivk"),
        //     &ivk_preimage,
        //     constants::CRH_IVK_PERSONALIZATION
        // )?;

        // ivk.truncate(E::Fs::CAPACITY as usize);                   
        

        Ok(())        
    }
}

#[cfg(test)]
    use pairing::bls12_381::*;
    use rand::{SeedableRng, Rng, XorShiftRng};    
    use super::circuit_test::TestConstraintSystem;
    use scrypto::jubjub::{JubjubBls12, fs, edwards};       

    
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
