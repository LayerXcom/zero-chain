#[cfg(feature = "std")]
use ::std::{vec::Vec, fmt, write};
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;
#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;
use crate::PARAMS;
use crate::{LeftCiphertext, RightCiphertext};
use zcrypto::elgamal;
use pairing::{
    bls12_381::{Bls12, Fr},
    io
};
use parity_codec::{Encode, Decode};
use core::convert::{TryInto, TryFrom};

#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Ciphertext(Vec<u8>);

impl TryFrom<elgamal::Ciphertext<Bls12>> for Ciphertext {
    type Error = io::Error;

    fn try_from(point: elgamal::Ciphertext<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 64];
        point.write(&mut writer[..])?;

        Ok(Ciphertext(writer.to_vec()))
    }
}

impl TryFrom<&elgamal::Ciphertext<Bls12>> for Ciphertext {
    type Error = io::Error;

    fn try_from(point: &elgamal::Ciphertext<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 64];
        point.write(&mut writer[..])?;

        Ok(Ciphertext(writer.to_vec()))
    }
}

impl TryFrom<Ciphertext> for elgamal::Ciphertext<Bls12> {
    type Error = io::Error;

    fn try_from(ct: Ciphertext) -> Result<Self, io::Error> {
        elgamal::Ciphertext::read(&mut &ct.0[..], &*PARAMS)
    }
}

impl TryFrom<&Ciphertext> for elgamal::Ciphertext<Bls12> {
    type Error = io::Error;

    fn try_from(ct: &Ciphertext) -> Result<Self, io::Error> {
        elgamal::Ciphertext::read(&mut &ct.0[..], &*PARAMS)
    }
}

impl Ciphertext {
    pub fn from_slice(slice: &[u8]) -> Self {
        Ciphertext(slice.to_vec())
    }

    pub fn from_left_right(left: LeftCiphertext, right: RightCiphertext) -> Result<Self, io::Error> {
        elgamal::Ciphertext::new(
            left.try_into()?,
            right.try_into()?
        )
        .try_into()
        .map_err(|_| io::Error::InvalidData)
    }

    pub fn add(&self, other: &Self) -> Result<Self, io::Error> {
        elgamal::Ciphertext::<Bls12>::try_from(self)?
            .add_no_params(&elgamal::Ciphertext::<Bls12>::try_from(other)?)
            .try_into()
    }

    pub fn sub(&self, other: &Self) -> Result<Self, io::Error> {
        elgamal::Ciphertext::<Bls12>::try_from(self)?
            .sub_no_params(&elgamal::Ciphertext::<Bls12>::try_from(other)?)
            .try_into()
    }
}

#[cfg(feature = "std")]
impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x")?;
        for i in &self.0 {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl AsBytesRef for Ciphertext {
    fn as_bytes_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Ciphertext {
    pub fn into_xy_left(&self) -> Result<(Fr, Fr), io::Error> {
        let left_point = elgamal::Ciphertext::<Bls12>::try_from(self)?
            .left.into_xy();

        Ok(left_point)
    }

    pub fn into_xy_right(&self) -> Result<(Fr, Fr), io::Error> {
        let right_point = elgamal::Ciphertext::<Bls12>::try_from(self)?
            .right.into_xy();

        Ok(right_point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use jubjub::curve::{FixedGenerators, JubjubBls12};
    use parity_codec::{Encode, Decode};
    use keys::EncryptionKey;

    fn gen_ciphertext() -> elgamal::Ciphertext::<Bls12> {
        let rng_seed = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let rng_r = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;
        let randomness = rng_r.gen();
        let seed: [u8; 32] = rng_seed.gen();

        let enc_key = EncryptionKey::from_seed(&seed[..], params).unwrap();
        let amount: u32 = 5 as u32;

        elgamal::Ciphertext::encrypt(amount, &randomness, &enc_key, p_g, params)
    }

    #[test]
    fn test_ciphertext_into_from() {
        let ciphertext_from = gen_ciphertext();
        let ciphertext = Ciphertext::try_from(&ciphertext_from).unwrap();
        let ciphertext_into = ciphertext.try_into().unwrap();

        assert!(ciphertext_from == ciphertext_into);
    }

    #[test]
    fn test_ciphertext_encode_decode() {
        let ciphertext = gen_ciphertext();
        let ciphertext_b = Ciphertext::try_from(&ciphertext).unwrap();

        let encoded_cipher = ciphertext_b.encode();
        let decoded_cipher = Ciphertext::decode(&mut encoded_cipher.as_slice()).unwrap();

        assert_eq!(ciphertext_b, decoded_cipher);
    }

    #[test]
    fn test_ciphertext_rw() {
        let ciphertext = gen_ciphertext();

        let mut buf = [0u8; 64];
        ciphertext.write(&mut &mut buf[..]).unwrap();

        let ciphertext_a = Ciphertext(buf.to_vec());
        let ciphertext_b = Ciphertext::try_from(&ciphertext).unwrap();

        assert_eq!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn test_from_left_right() {
        let ciphertext = gen_ciphertext();

        let mut buf = [0u8; 64];
        ciphertext.write(&mut &mut buf[..]).unwrap();

        let left = LeftCiphertext::from_slice(&buf[..32]);
        let right = RightCiphertext::from_slice(&buf[32..]);

        let ciphertext_from = Ciphertext::from_left_right(left, right).unwrap();
        let ciphertext2 = ciphertext_from.try_into().unwrap();

        assert!(ciphertext == ciphertext2);
    }
}
