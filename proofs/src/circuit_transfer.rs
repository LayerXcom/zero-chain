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
    pub proof_generation_key: Option<ProofGenerationKey<E>>,
    // The payment address associated with the note
    pub prover_payment_address: Option<PaymentAddress<E>>,
    // The payment address  of the recipient
    pub recipient_payment_address: Option<PaymentAddress<E>>,
    pub old_value: Option<u64>, 
    pub prover_value: Option<u64>,
    pub receiver_value: Option<u64>,
    pub esk: Option<E::Fs>,
    // Re-randomization of the public key
    pub ar: Option<E::Fs>,
}

impl<'a, E: JubjubEngine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;

        // Prover witnesses recipient_g_d, ensuring it's on the curve.
        let recipient_g_d = ecc::EdwardsPoint::witness(
            cs.namespace(|| "witness recipient_g_d"),
            self.recipient_payment_address.as_ref().and_then(|a| a.g_d(params)),
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

        // compute note contents:
        // value (in big endian) followed by g_d and pk_d
        let mut old_note_contents = vec![];
        // let mut prover_note_contents = vec![];
        // let mut receiver_note_contents = vec![];

        let mut value_num: num::Num<E> = num::Num::zero();

        {
            let old_value_bits = boolean::u64_into_boolean_vec_le(
                cs.namespace(|| "value"),
                self.old_value
            )?;

            let mut coeff = E::Fr::one();
            for bit in &old_value_bits {
                value_num = value_num.add_bool_with_coeff(
                    CS::one(),
                    bit,
                    coeff
                );
                coeff.double();
            }

            old_note_contents.extend(old_value_bits);
        }        

        old_note_contents.extend(
            prover_g_d.repr(cs.namespace(|| "representation of prover_g_d"))?
        );

        old_note_contents.extend(
            prover_pk_d.repr(cs.namespace(|| "representation of prover_pk_d"))?
        );

        assert_eq!(
            old_note_contents.len(), 
            64 + // old_value_bits
            256 + // prover_g_d
            256 // prover_pk_d
        );

        // Compute and expose H(old_note_contents) publicly.
        let hash_old_note = blake2s::blake2s(
            cs.namespace(|| "hash_old_note computation"),
            &old_note_contents,
            constants::PRF_NF_PERSONALIZATION
        )?;

        multipack::pack_into_inputs(cs.namespace(|| "pack nullifier"), &hash_old_note)
    }
}

// fn expose_hash_note<E, CS>(
//     mut cs: CS,
//     value: Option<u64>,
// ) -> Result<(), SynthesisError>
//     where E: JubjubEngine, CS: ConstraintSystem<E>
// {

// }

#[test]
fn test_transfer_circuit() {
    assert_eq!(4, 2+2);
}
