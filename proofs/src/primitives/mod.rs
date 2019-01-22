use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,    
};

use scrypto::{constants, group_hash::group_hash};

use scrypto::jubjub::{
    JubjubEngine,
    JubjubParams,
    edwards,
    PrimeOrder,
    FixedGenerators
};

use blake2_rfc::blake2s::Blake2s;

#[derive(Clone)]
pub struct ProofGenerationKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nsk: E::Fs
}

impl<E: JubjubEngine> ProofGenerationKey<E> {
    pub fn into_viewing_key(&self, params: &E::Params) -> ViewingKey<E> {
        ViewingKey {
            ak: self.ak.clone(),
            nk: params.generator(FixedGenerators::ProofGenerationKey).mul(self.nsk, params)
        }
    }
}

pub struct ViewingKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nk: edwards::Point<E, PrimeOrder>
}

impl<E: JubjubEngine> ViewingKey<E> {
    pub fn rk(
        &self,
        ar: E::Fs,
        params: &E::Params
    ) -> edwards::Point<E, PrimeOrder> {
        self.ak.add(
            &params.generator(FixedGenerators::SpendingKeyGenerator).mul(ar, params),
            params
        )
    }

    pub fn ivk(&self) -> E::Fs {
        let mut preimage = [0; 64];
        self.ak.write(&mut preimage[0..32]).unwrap();
        self.nk.write(&mut preimage[32..64]).unwrap();

        let mut h = Blake2s::with_params(32, &[], &[], constants::CRH_IVK_PERSONALIZATION);
        h.update(&preimage);
        let mut h = h.finalize().as_ref().to_vec();

        h[31] &= 0b0000_0111;
        let mut e = <E::Fs as PrimeField>::Repr::default();

        // Reads a little endian integer into this representation.
        e.read_le(&h[..]).unwrap();
        E::Fs::from_repr(e).expect("should be a vaild scalar")
    }

    pub fn into_payment_address(
        &self,
        diversifier: Diversifier,
        params: &E::Params
    ) -> Option<PaymentAddress<E>>
    {
        diversifier.g_d(params).map(|g_d| {
            let pk_d = g_d.mul(self.ivk(), params);

            PaymentAddress{
                pk_d: pk_d,
                diversifier: diversifier
            }
        })
    }
}

#[derive(Copy, Clone)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d<E: JubjubEngine>(
        &self,
        params: &E::Params
    ) -> Option<edwards::Point<E, PrimeOrder>>
    {
        group_hash::<E>(&self.0, constants::KEY_DIVERSIFICATION_PERSONALIZATION, params)
    }
}


#[derive(Clone)]
pub struct PaymentAddress<E: JubjubEngine> {
    pub pk_d: edwards::Point<E, PrimeOrder>,
    pub diversifier: Diversifier
}

impl<E: JubjubEngine> PaymentAddress<E> {
    pub fn g_d(
        &self,
        params: &E::Params
    ) -> Option<edwards::Point<E, PrimeOrder>>
    {
        self.diversifier.g_d(params)
    }

    // pub fn create_note(
    //     &self,
    //     value: u64,
    //     randomness: E::Fs,
    //     params: &E::Params
    // ) -> Option<Note<E>>
    // {
    //     Some(Note{
    //         value: value,
    //         r: randomness,
    //     })
    // }
}

// pub struct Note<E: JubjubEngine> {
//     pub value: u64,
//     // The commitment randomness
//     pub r: E::Fs,
// }
