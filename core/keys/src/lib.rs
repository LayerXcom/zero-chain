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
pub const CRH_BDK_PERSONALIZATION: &'static [u8; 8] = b"zech_bdk";
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &'static [u8; 8] = b"zech_div";

// fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bResult {
//     prf_expand_vec(sk, &vec![t])
// }

// fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bResult {
//     let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
//     h.update(sk);
//     for t in ts {
//         h.update(t);
//     }
//     h.finalize()
// }

// /// Extend the secret key to 64 bits for the scalar field generation.
// pub fn prf_extend_wo_t(sk: &[u8]) -> Blake2bResult {
//     let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
//     h.update(sk);
//     h.finalize()
// }

// #[derive(Debug, Clone, PartialEq)]
// pub struct ExpandedSpendingKey<E: JubjubEngine> {
//     pub ask: E::Fs,
//     pub nsk: E::Fs,
// }

// impl<E: JubjubEngine> ExpandedSpendingKey<E> {
//     /// Generate the 64bytes extend_spending_key from the 32bytes spending key.
//     pub fn from_spending_key(sk: &[u8]) -> Self {
//         let ask = E::Fs::to_uniform(prf_expand(sk, &[0x00]).as_bytes());
//         let nsk = E::Fs::to_uniform(prf_expand(sk, &[0x01]).as_bytes());
//         ExpandedSpendingKey { ask, nsk }
//     }

//     pub fn into_proof_generation_key(&self, params: &E::Params) -> ProofGenerationKey<E> {
//         ProofGenerationKey {
//             ak: params.generator(FixedGenerators::Diversifier).mul(self.ask, params),
//             nsk: self.nsk,
//         }
//     }

//     pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
//         self.ask.into_repr().write_le(&mut writer)?;
//         self.nsk.into_repr().write_le(&mut writer)?;
//         Ok(())
//     }

//     pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
//         let mut ask_repr = <E::Fs as PrimeField>::Repr::default();
//         ask_repr.read_le(&mut reader)?;
//         let ask = E::Fs::from_repr(ask_repr)
//             .map_err(|_| io::Error::InvalidData)?;

//         let mut nsk_repr = <E::Fs as PrimeField>::Repr::default();
//         nsk_repr.read_le(&mut reader)?;
//         let nsk = E::Fs::from_repr(nsk_repr)
//             .map_err(|_| io::Error::InvalidData)?;

//         Ok(ExpandedSpendingKey {
//             ask,
//             nsk,
//         })
//     }
// } 

// #[derive(Clone)]
// pub struct ProofGenerationKey<E: JubjubEngine> (
//     edwards::Point<E, PrimeOrder>
// );   

// impl<E: JubjubEngine> ProofGenerationKey<E> {
//     /// Generate viewing key from proof generation key.
//     pub fn into_viewing_key(&self, params: &E::Params) -> ViewingKey<E> {
//         ViewingKey {
//             ak: self.ak.clone(),
//             nk: params.generator(FixedGenerators::Diversifier).mul(self.nsk, params)
//         }
//     }
// }

pub fn bytes_to_fs<E: JubjubEngine>(bytes: &[u8]) -> E::Fs {
    let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
    h.update(bytes);        
    let res = h.finalize();
    E::Fs::to_uniform(res.as_bytes())
}

#[derive(Clone)]
pub struct ProofGenerationKey<E: JubjubEngine> (
    pub edwards::Point<E, PrimeOrder>    
);

impl<E: JubjubEngine> ProofGenerationKey<E> {
    /// Generate proof generation key key from origin key
    pub fn from_origin_key(
        origin_key: &E::Fs, 
        params: &E::Params
    ) -> Self 
    {
        ProofGenerationKey (
            params
                .generator(FixedGenerators::Diversifier)
                .mul(origin_key.into_repr(), params)            
        )
    }

    /// Generate proof generation key from origin key cast as bytes
    pub fn from_ok_bytes(
        ok: &[u8],
        params: &E::Params
    ) -> Self
    {
        Self::from_origin_key(&bytes_to_fs::<E>(ok), params)
    }

    /// Generate the randomized signature-verifying key
    pub fn rvk(
        &self,
        alpha: E::Fs,
        params: &E::Params
    ) -> edwards::Point<E, PrimeOrder> {
        self.0.add(
            &params.generator(FixedGenerators::Diversifier).mul(alpha, params),
            params
        )
    }

    /// Generate the decryption key
    pub fn bdk(&self) -> E::Fs {
        let mut preimage = [0; 32];
        self.0.write(&mut &mut preimage[..]).unwrap();        

        let mut h = Blake2s::with_params(32, &[], &[], CRH_BDK_PERSONALIZATION);
        h.update(&preimage);
        let mut h = h.finalize().as_ref().to_vec();

        h[31] &= 0b0000_0111;
        let mut e = <E::Fs as PrimeField>::Repr::default();

        // Reads a little endian integer into this representation.
        e.read_le(&mut &h[..]).unwrap();
        E::Fs::from_repr(e).expect("should be a vaild scalar")
    }

    /// Generate the payment address from proof generation key.
    pub fn into_encryption_key(
        &self,        
        params: &E::Params
    ) -> EncryptionKey<E>
    {
        let pk_d = params
            .generator(FixedGenerators::Diversifier)
            .mul(self.bdk(), params);

        EncryptionKey(pk_d)
    }
}

#[derive(Clone, PartialEq)]
pub struct EncryptionKey<E: JubjubEngine> (
    pub edwards::Point<E, PrimeOrder>    
);

impl<E: JubjubEngine> EncryptionKey<E> {    
    pub fn from_origin_key(
        origin_key: &E::Fs,
        params: &E::Params,
    ) -> Self
    {
        let proof_generation_key = ProofGenerationKey::from_origin_key(origin_key, params);
        proof_generation_key.into_encryption_key(params)
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.write(&mut writer)?;        
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let pk_d = edwards::Point::<E, _>::read(reader, params)?;
        let pk_d = pk_d.as_prime_order(params).unwrap();        
        Ok(EncryptionKey(pk_d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use jubjub::curve::{JubjubBls12, fs};
    use pairing::bls12_381::Bls12;
    
    #[test]
    fn test_encryption_key_read_write() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let origin_key = fs::Fs::rand(rng);   
        let addr1 = EncryptionKey::from_origin_key(origin_key, params);

        let mut v = vec![];
        addr1.write(&mut v).unwrap();
        let addr2 = EncryptionKey::<Bls12>::read(&mut v.as_slice(), params).unwrap();
        assert!(addr1 == addr2);
    }
}
