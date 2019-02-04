use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,    
};

use scrypto::group_hash::group_hash;

use scrypto::jubjub::{
    JubjubEngine,
    JubjubParams,
    edwards,
    PrimeOrder,
    FixedGenerators,
    ToUniform,
};

use blake2_rfc::{
    blake2s::Blake2s, 
    blake2b::{Blake2b, Blake2bResult}
};
use zcrypto::{constants, mimc};
use codec::{Encode, Decode};

fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bResult {
    prf_expand_vec(sk, &vec![t])
}

fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], constants::PRF_EXPAND_PERSONALIZATION);
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

pub struct ExpandedSpendingKey<E: JubjubEngine> {
    ask: E::Fs,
    nsk: E::Fs,
}

impl<E: JubjubEngine> ExpandedSpendingKey<E> {
    fn from_spending_key(sk: &[u8]) -> Self {
        let ask = E::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
        let nsk = E::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
        ExpandedSpendingKey { ask, nsk }
    }
} 


#[derive(Clone, Copy, Default, Encode, Decode)]
pub struct ValueCommitment<E: JubjubEngine> {
    pub value: u64,
    pub randomness: E::Fs,
}

impl<E: JubjubEngine> ValueCommitment<E> 
where <E as JubjubEngine>::Fs: Encode + Decode {
    pub fn cm(
        &self,
        params: &E::Params,        
    ) -> edwards::Point<E, PrimeOrder>
    {
        params.generator(FixedGenerators::ValueCommitmentValue)
            .mul(self.value, params)
            .add(
                &params.generator(FixedGenerators::ValueCommitmentRandomness)
                .mul(self.randomness, params),
                params
            )
    }   
}

// #[derive(Clone, Encode, Decode, Default)]
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

// #[derive(Clone, Encode, Decode, Default)]
pub struct ViewingKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nk: edwards::Point<E, PrimeOrder>
}

impl<E: JubjubEngine> ViewingKey<E> {
    pub fn from_expanded_spending_key(
        expsk: &ExpandedSpendingKey<E>, 
        params: &E::Params
    ) -> Self 
    {
        ViewingKey {
            ak: params
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(expsk.ask, params),
            nk: params
                .generator(FixedGenerators::SpendingKeyGenerator)
                .mul(expsk.nsk, params),
        }
    }

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

// pub struct Diversifier(pub [u8; 11]);
#[derive(Clone, Encode, Decode, Default)]
pub struct Diversifier;

impl Diversifier {
    pub fn g_d<E: JubjubEngine>(
        &self,
        params: &E::Params
    ) -> Option<edwards::Point<E, PrimeOrder>>
    {
        group_hash::<E>(&self.encode(), constants::KEY_DIVERSIFICATION_PERSONALIZATION, params)
    }
}


#[derive(Clone, Encode, Decode, Default)]
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
}
