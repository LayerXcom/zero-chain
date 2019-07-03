//! (TODO) Alias module of `/core/keys` crate due to std and no_std compatibility.

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
            Unknown,
        },
        redjubjub::PrivateKey,
};
use std::io;
use blake2_rfc::{
    blake2s::Blake2s,
    blake2b::{Blake2b, Blake2bResult},
};

pub const PRF_EXPAND_PERSONALIZATION: &'static [u8; 16] = b"zech_ExpandSeed_";
pub const CRH_BDK_PERSONALIZATION: &'static [u8; 8] = b"zech_bdk";
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &'static [u8; 8] = b"zech_div";

pub fn prf_expand(sk: &[u8], t: &[u8]) -> Blake2bResult {
    prf_expand_vec(sk, &[t])
}

pub fn prf_expand_vec(sk: &[u8], ts: &[&[u8]]) -> Blake2bResult {
    let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
    h.update(sk);
    for t in ts {
        h.update(t);
    }
    h.finalize()
}

/// Each account needs the spending key to send transactions.
#[derive(Clone, Debug, PartialEq)]
pub struct SpendingKey<E: JubjubEngine>(pub E::Fs);

impl<E: JubjubEngine> Copy for SpendingKey<E> {}

impl<E: JubjubEngine> SpendingKey<E> {
    pub fn from_seed(seed: &[u8]) -> Self {
        // TODO: let fs = E::Fs::to_uniform(prf_expand(seed, &[0x00]).as_bytes());
        let mut h = Blake2b::with_params(64, &[], &[], PRF_EXPAND_PERSONALIZATION);
        h.update(seed);
        let res = h.finalize();
        let fs = E::Fs::to_uniform(res.as_bytes());
        SpendingKey(fs)
    }

    /// Generate a re-randomized signature signing key
    pub fn into_rsk(
        &self,
        alpha: E::Fs,
    ) -> PrivateKey<E>
    {
        PrivateKey(self.0).randomize(alpha)
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut s_repr = <E::Fs as PrimeField>::Repr::default();
        s_repr.read_le(&mut reader)?;

        let fs = E::Fs::from_repr(s_repr).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Not in field."))?;

        Ok(SpendingKey(fs))
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.into_repr().write_le(&mut writer)?;
        Ok(())
    }

    pub fn into_bytes(&self) -> io::Result<[u8; 32]> {
        let mut res = [0u8; 32];
        self.write(&mut &mut res[..])?;
        Ok(res)
    }
}

/// Proof generation key is needed when each user generate zk-proofs.
/// (NOTE): To delegate proof generations,
/// user needs to pass the decryption key, not proof generation key
/// because of the current's statement in circuit.
#[derive(Clone, PartialEq, Debug)]
pub struct ProofGenerationKey<E: JubjubEngine> (
    pub edwards::Point<E, PrimeOrder>
);

/// Re-randomized signature verification key
#[derive(Clone)]
pub struct RandomizedSigVk<E: JubjubEngine>(
    pub edwards::Point<E, PrimeOrder>
);

/// Decryption key for decrypting transferred ammounts and balances
#[derive(Clone)]
pub struct DecryptionKey<E: JubjubEngine>(pub E::Fs);

impl<E: JubjubEngine> Copy for DecryptionKey<E> {}

impl<E: JubjubEngine> DecryptionKey<E> {
    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut dec_key_repr = <E::Fs as PrimeField>::Repr::default();
        dec_key_repr.read_le(&mut reader)?;

        let dec_key_fs = E::Fs::from_repr(dec_key_repr)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Not in field."))?;
        Ok(DecryptionKey(dec_key_fs))
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.into_repr().write_le(&mut writer)?;
        Ok(())
    }
}

impl<E: JubjubEngine> ProofGenerationKey<E> {
    /// Generate a proof generation key from a seed
    pub fn from_seed(
        seed: &[u8],
        params: &E::Params
    ) -> Self
    {
        Self::from_spending_key(
            &SpendingKey::from_seed(seed),
            params
        )
    }

    /// Generate a proof generation key from a spending key
    pub fn from_spending_key(
        spending_key: &SpendingKey<E>,
        params: &E::Params
    ) -> Self
    {
        ProofGenerationKey (
            params
                .generator(FixedGenerators::NoteCommitmentRandomness)
                .mul(spending_key.0.into_repr(), params)
        )
    }

    /// Generate the randomized signature-verifying key
    pub fn into_rvk(
        &self,
        alpha: E::Fs,
        params: &E::Params
    ) -> RandomizedSigVk<E> {
        let point = self.0.add(
            &params.generator(FixedGenerators::NoteCommitmentRandomness).mul(alpha, params),
            params
        );

        RandomizedSigVk(point)
    }

    /// Generate a decryption key
    pub fn into_decryption_key(&self) -> io::Result<DecryptionKey<E>> {
        let mut preimage = [0; 32];
        self.0.write(&mut &mut preimage[..])?;

        let mut h = Blake2s::with_params(32, &[], &[], CRH_BDK_PERSONALIZATION);
        h.update(&preimage);
        let mut h = h.finalize().as_ref().to_vec();

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;
        let mut e = <E::Fs as PrimeField>::Repr::default();

        // Reads a little endian integer into this representation.
        e.read_le(&mut &h[..])?;

        let fs = E::Fs::from_repr(e)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Not in field."))?;

        Ok(DecryptionKey(fs))
    }

    /// Generate a encryption key from a proof generation key.
    pub fn into_encryption_key(
        &self,
        params: &E::Params
    ) -> io::Result<EncryptionKey<E>>
    {
        let pk_d = params
            .generator(FixedGenerators::NoteCommitmentRandomness)
            .mul(self.into_decryption_key()?.0, params);

        Ok(EncryptionKey(pk_d))
    }

    pub fn add(&self, other: &Self, params: &E::Params) -> Self {
        let point = self.0.add(&other.0, params);
        ProofGenerationKey(point)
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.write(&mut writer)?;
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let point = edwards::Point::<E, Unknown>::read(reader, params)?;
        let point = point
            .as_prime_order(params)
            .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Not in the prime order subgroup."))?;

        Ok(ProofGenerationKey(point))
    }

    pub fn into_bytes(&self) -> io::Result<[u8; 32]> {
        let mut res = [0u8; 32];
        self.write(&mut res[..])?;

        Ok(res)
    }
}

/// Encryption key can be used for encrypting transferred amounts and balances
/// and also alias of account id in Zerochain.
#[derive(Clone, PartialEq, Debug)]
pub struct EncryptionKey<E: JubjubEngine> (
    pub edwards::Point<E, PrimeOrder>
);

impl<E: JubjubEngine> EncryptionKey<E> {
    pub fn from_seed(
        seed: &[u8],
        params: &E::Params
    ) -> io::Result<Self>
    {
        Self::from_spending_key(&SpendingKey::from_seed(seed), params)
    }

    pub fn from_spending_key(
        spending_key: &SpendingKey<E>,
        params: &E::Params,
    ) -> io::Result<Self>
    {
        let proof_generation_key = ProofGenerationKey::from_spending_key(spending_key, params);
        proof_generation_key.into_encryption_key(params)
    }

    pub fn from_decryption_key(
        decryption_key: &DecryptionKey<E>,
        params: &E::Params,
    ) -> Self
    {
        let pk_d = params
            .generator(FixedGenerators::NoteCommitmentRandomness)
            .mul(decryption_key.0, params);

        EncryptionKey(pk_d)
    }

    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.0.write(&mut writer)?;
        Ok(())
    }

    pub fn read<R: io::Read>(reader: &mut R, params: &E::Params) -> io::Result<Self> {
        let pk_d = edwards::Point::<E, Unknown>::read(reader, params)?;
        let pk_d = pk_d
            .as_prime_order(params)
            .ok_or(io::Error::new(io::ErrorKind::InvalidInput, "Not in the prime order subgroup."))?;

        Ok(EncryptionKey(pk_d))
    }

    pub fn into_bytes(&self) -> io::Result<[u8; 32]> {
        let mut res = [0u8; 32];
        self.write(&mut res[..])?;

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng, Rand};
    use scrypto::jubjub::{JubjubBls12, fs};
    use pairing::bls12_381::Bls12;

    #[test]
    fn test_encryption_key_read_write() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let spending_key = fs::Fs::rand(rng);
        let addr1 = EncryptionKey::from_spending_key(&SpendingKey(spending_key), params).unwrap();

        let mut v = vec![];
        addr1.write(&mut v).unwrap();
        let addr2 = EncryptionKey::<Bls12>::read(&mut v.as_slice(), params).unwrap();
        assert!(addr1 == addr2);
    }
}

