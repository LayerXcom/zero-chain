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
    pub params: &'a E::Params, // TODO
    pub sender_spending_key: Option<E::Fs>,
    pub receiver_public_ley: Option<ProofGenerationKey<E>>,
    old_value: Option<u64>, 
    sender_value: Option<u64>,
    receiver_value: Option<u64>,
    ephmeral_secret_key: Option<E::Fs>,
}

impl<'a, E: Engine> Circuit<E> for Transfer<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {

    }
}



