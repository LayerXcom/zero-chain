use pairing::{
    PrimeField,
    PrimeFieldRepr,       
};    

use scrypto::{
        jubjub::{
            JubjubEngine,
            JubjubParams,
            edwards,
            PrimeOrder,
            FixedGenerators,
            ToUniform,
        },
        group_hash::group_hash,
};
use std::io::{self, Read, Write};

use blake2_rfc::{
    blake2s::Blake2s, 
    blake2b::{Blake2b, Blake2bResult}
};

pub const PRF_EXPAND_PERSONALIZATION: &'static [u8; 16] = b"zech_ExpandSeed_";
pub const CRH_IVK_PERSONALIZATION: &'static [u8; 8] = b"zech_ivk";
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &'static [u8; 8] = b"zech_div";

// TODO: Change OsRng to ChachaRng
use rand::{OsRng, Rand, Rng};

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

#[derive(Debug, Clone, PartialEq)]
pub struct ExpandedSpendingKey<E: JubjubEngine> {
    ask: E::Fs,
    nsk: E::Fs,
}

impl<E: JubjubEngine> ExpandedSpendingKey<E> {
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask = E::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
        let nsk = E::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
        ExpandedSpendingKey { ask, nsk }
    }

     pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.ask.into_repr().write_le(&mut writer)?;
        self.nsk.into_repr().write_le(&mut writer)?;
        Ok(())
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut ask_repr = <E::Fs as PrimeField>::Repr::default();
        ask_repr.read_le(&mut reader)?;
        let ask = E::Fs::from_repr(ask_repr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut nsk_repr = <E::Fs as PrimeField>::Repr::default();
        nsk_repr.read_le(&mut reader)?;
        let nsk = E::Fs::from_repr(nsk_repr)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(ExpandedSpendingKey {
            ask,
            nsk,
        })
    }
} 

#[derive(Clone)]
pub struct ValueCommitment<E: JubjubEngine> {
    pub value: u64,
    pub randomness: E::Fs,
    pub is_negative: bool,
}

impl<E: JubjubEngine> ValueCommitment<E> {
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

const DIVERSIFIER_SIZE: usize = 11;

#[derive(Clone)]
pub struct Diversifier(pub [u8; DIVERSIFIER_SIZE]);

impl Diversifier {    
    pub fn new<E: JubjubEngine>(params: &E::Params) 
        -> Result<Diversifier, ()> 
    { 
        loop {
            let mut d_j = [0u8; 11];
            OsRng::new().unwrap().fill_bytes(&mut d_j[..]);
            let d_j = Diversifier(d_j);

            match d_j.g_d::<E>(params) {
                Some(_) => return Ok(d_j),
                None => {}
            }   
        }                      
    }

    pub fn g_d<E: JubjubEngine>(
        &self,
        params: &E::Params
    ) -> Option<edwards::Point<E, PrimeOrder>>
    {
        group_hash::<E>(&self.0, KEY_DIVERSIFICATION_PERSONALIZATION, params)
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
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

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.pk_d.write(&mut writer)?;
        self.diversifier.write(&mut writer)?;
        Ok(())
    }
}
