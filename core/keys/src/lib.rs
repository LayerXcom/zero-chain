#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
mod std {
    pub use ::core::*;
    pub use crate::alloc::vec;
    pub use crate::alloc::string;
    pub use crate::alloc::boxed;
    pub use crate::alloc::borrow;    
}

use pairing::{
    PrimeField,
    PrimeFieldRepr,    
    io,    
};    

use jubjub::{
        curve::{
            JubjubEngine,
            JubjubParams,
            edwards,
            PrimeOrder,
            FixedGenerators,
            ToUniform,
        },        
};

use blake2_rfc::{
    blake2s::Blake2s, 
    blake2b::{Blake2b, Blake2bResult}
};

pub const PRF_EXPAND_PERSONALIZATION: &'static [u8; 16] = b"zech_ExpandSeed_";
pub const CRH_IVK_PERSONALIZATION: &'static [u8; 8] = b"zech_ivk";
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &'static [u8; 8] = b"zech_div";

fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bResult {
    prf_expand_vec(sk, &vec![t])
}

fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

/// Extend the secret key to 64 bits for the scalar field generation.
pub fn prf_extend_wo_t(sk: &[u8]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
    h.update(sk);
    h.finalize()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedSpendingKey<E: JubjubEngine> {
    pub ask: E::Fs,
    pub nsk: E::Fs,
}

impl<E: JubjubEngine> ExpandedSpendingKey<E> {
    /// Generate the 64bytes extend_spending_key from the 32bytes spending key.
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask = E::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
        let nsk = E::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
        ExpandedSpendingKey { ask, nsk }
    }

    pub fn into_proof_generation_key(&self, params: &E::Params) -> ProofGenerationKey<E> {
        ProofGenerationKey {
            ak: params.generator(FixedGenerators::ProofGenerationKey).mul(self.ask, params),
            nsk: self.nsk,
        }
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.ask.into_repr().write_le(&mut writer)?;
        self.nsk.into_repr().write_le(&mut writer)?;
        Ok(())
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut ask_repr = <E::Fs as PrimeField>::Repr::default();
        ask_repr.read_le(&mut reader)?;
        let ask = E::Fs::from_repr(ask_repr)
            .map_err(|_| io::Error::InvalidData)?;

        let mut nsk_repr = <E::Fs as PrimeField>::Repr::default();
        nsk_repr.read_le(&mut reader)?;
        let nsk = E::Fs::from_repr(nsk_repr)
            .map_err(|_| io::Error::InvalidData)?;

        Ok(ExpandedSpendingKey {
            ask,
            nsk,
        })
    }
} 

#[derive(Clone, Default)]
pub struct ValueCommitment<E: JubjubEngine> {
    pub value: u64,
    pub randomness: E::Fs,
    pub is_negative: bool,
}

impl<E: JubjubEngine> ValueCommitment<E> {
    /// Generate pedersen commitment from the value and randomness parameters
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

    /// Change the value from the positive representation to negative one.
    pub fn change_sign(&self) -> Self {
        ValueCommitment {
            value: self.value,
            randomness: self.randomness,
            is_negative: !self.is_negative,
        }
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nsk: E::Fs
}

impl<E: JubjubEngine> ProofGenerationKey<E> {
    /// Generate viewing key from proof generation key.
    pub fn into_viewing_key(&self, params: &E::Params) -> ViewingKey<E> {
        ViewingKey {
            ak: self.ak.clone(),
            nk: params.generator(FixedGenerators::ProofGenerationKey).mul(self.nsk, params)
        }
    }
}

#[derive(Clone)]
pub struct ViewingKey<E: JubjubEngine> {
    pub ak: edwards::Point<E, PrimeOrder>,
    pub nk: edwards::Point<E, PrimeOrder>
}

impl<E: JubjubEngine> ViewingKey<E> {
    /// Generate viewing key from extended spending key
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

    /// Generate the signature verifying key
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

    /// Generate the internal viewing key
    pub fn ivk(&self) -> E::Fs {
        let mut preimage = [0; 64];
        self.ak.write(&mut &mut preimage[0..32]).unwrap();
        self.nk.write(&mut &mut preimage[32..64]).unwrap();

        let mut h = Blake2s::with_params(32, &[], &[], CRH_IVK_PERSONALIZATION);
        h.update(&preimage);
        let mut h = h.finalize().as_ref().to_vec();

        h[31] &= 0b0000_0111;
        let mut e = <E::Fs as PrimeField>::Repr::default();

        // Reads a little endian integer into this representation.
        e.read_le(&mut &h[..]).unwrap();
        E::Fs::from_repr(e).expect("should be a vaild scalar")
    }

    /// Generate the payment address from viewing key.
    pub fn into_payment_address(
        &self,        
        params: &E::Params
    ) -> PaymentAddress<E>
    {
        let pk_d = params
            .generator(FixedGenerators::Diversifier)
            .mul(self.ivk(), params);

        PaymentAddress(pk_d)
    }
}

#[derive(Clone, PartialEq)]
pub struct PaymentAddress<E: JubjubEngine> (
    pub edwards::Point<E, PrimeOrder>    
);

impl<E: JubjubEngine> PaymentAddress<E> {    
    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.write(&mut writer)?;        
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let pk_d = edwards::Point::<E, _>::read(reader, params)?;
        let pk_d = pk_d.as_prime_order(params).unwrap();        
        Ok(PaymentAddress(pk_d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use jubjub::curve::JubjubBls12;    
    use pairing::bls12_381::Bls12;
    
    #[test]
    fn test_payment_address_read_write() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed[..]);

        let ex_sk = ExpandedSpendingKey::<Bls12>::from_spending_key(&seed[..]);
        let viewing_key = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk, params);        
        let addr1 = viewing_key.into_payment_address(params);

        let mut v = vec![];
        addr1.write(&mut v).unwrap();
        let addr2 = PaymentAddress::<Bls12>::read(&mut v.as_slice(), params).unwrap();
        assert!(addr1 == addr2);
    }
}
