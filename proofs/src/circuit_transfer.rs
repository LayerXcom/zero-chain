use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,
    Engine,
};

use bellman::{
    SynthesisError,
    ConstraintSystem,
    Circuit,
};

use jubjub::{
    JubjubEngine,
    FixedGenerators
};

use sapling_crypt::{
    ecc,
    pedersen_hash
};

pub struct Transfer<'a, E: JubjubEngine> {
    pub params: &'a E::Params, 
    pub proof_generation_key: Option<ProofGenerationKey<E>>,
    // The payment address associated with the note
    pub sender_payment_address: Option<PaymentAddress<E>>,
    // The payment address  of the recipient
    pub recipient_payment_address: Option<PaymentAddress<E>>,
    pub old_value: Option<u64>, 
    pub sender_value: Option<u64>,
    pub receiver_value: Option<u64>,
    pub ephmeral_secret_key: Option<E::Fs>,
    // Re-randomization of the public key
    pub ar: Option<E::Fs>,
}

impl<'a, E: Engine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let params = self.params;

        // Prover witnesses g_d, ensuring it's on the curve.
        let g_d = ecc::EdwardsPoint::witnesses(
            cs.namespace(|| "witness g_d"),
            self.recipient_payment_address.as_ref().and_then(|a| a.g_d(params)),
            self.params
        )?;

        // Ensure g_d is large order.
        g_d.assert_not_small_order(
            cs.namespace(|| "g_d not small order"),
            self.params
        )?;
        
        let esk = boolean::field_into_boolean_vec_le(
            cs.namespace(|| "esk"),
            self.esk
        )?;

        // Create the ephemeral public key from g_d.
        let epk = g_d.mul(
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
        // TODO: large order check for ak
    }
}



