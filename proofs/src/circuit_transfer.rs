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
    pub sender_spending_key: Option<E::Fs>,
    // The payment address  of the recipient
    pub payment_address: Option<PaymentAddress<E>>,
    pub old_value: Option<u64>, 
    pub sender_value: Option<u64>,
    pub receiver_value: Option<u64>,
    pub ephmeral_secret_key: Option<E::Fs>,
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
            self.payment_address.as_ref().and_then(|a| a.g_d(params)),
            self.params
        )?;

        // Ensure g_d is large order.
        g_d.assert_not_small_order(
            cs.namespace(|| "g_d not small order"),
            self.params
        )?;

        // Create the ephemeral public key from g_d.
        let epk = g_d.mul(
            cs.namespace(|| "epk computation"),
            &esk,
            self.params
        )?;

        // Expose epk publicly.
        epk.inputize(cs.namespace(|| "epk"))?;
    }
}



