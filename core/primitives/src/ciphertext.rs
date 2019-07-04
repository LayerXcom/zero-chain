use crate::PARAMS;
use zcrypto::elgamal;
use pairing::bls12_381::Bls12;
use jubjub::curve::JubjubBls12;

#[cfg(feature = "std")]
use ::std::{vec::Vec, fmt, write};
#[cfg(not(feature = "std"))]
use crate::std::vec::Vec;

use parity_codec_derive::{Encode, Decode};
#[cfg(feature = "std")]
use substrate_primitives::hexdisplay::AsBytesRef;

#[derive(Eq, PartialEq, Clone, Default, Encode, Decode)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct Ciphertext(Vec<u8>);

pub trait ElgamalCiphertext {
    fn into_ciphertext(&self) -> Option<elgamal::Ciphertext<Bls12>>;
    fn from_ciphertext(ciphertext: &elgamal::Ciphertext<Bls12>) -> Self;
}

impl ElgamalCiphertext for Ciphertext {
    fn into_ciphertext(&self) -> Option<elgamal::Ciphertext<Bls12>> {
        elgamal::Ciphertext::read(&mut &self.0[..], &PARAMS as &JubjubBls12).ok()
    }

    fn from_ciphertext(ciphertext: &elgamal::Ciphertext<Bls12>) -> Self {
        let mut writer = [0u8; 64];
        ciphertext.write(&mut writer[..]).unwrap();
        Ciphertext(writer.to_vec())
    }
}

impl Ciphertext {
    pub fn from_slice(slice: &[u8]) -> Self {
        Ciphertext(slice.to_vec())
    }
}

impl Into<Ciphertext> for elgamal::Ciphertext<Bls12> {
    fn into(self) -> Ciphertext {
        Ciphertext::from_ciphertext(&self)
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


#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng, Rand};
    use pairing::PrimeField;
    use jubjub::curve::{FixedGenerators, JubjubBls12, fs::Fs, ToUniform, JubjubParams};
    use parity_codec::{Encode, Decode};
    use keys::EncryptionKey;

    #[test]
    fn test_ciphertext_into_from() {
        let rng_sk = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal::elgamal_extend(&sk).as_bytes()).into_repr();

        let rng_r = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r.fill_bytes(&mut randomness[..]);
        let r_fs = Fs::to_uniform(elgamal::elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let value: u32 = 5 as u32;

        let ciphertext1 = elgamal::Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);

        let ciphertext_b = Ciphertext::from_ciphertext(&ciphertext1);
        let ciphertext2 = ciphertext_b.into_ciphertext().unwrap();

        assert!(ciphertext1 == ciphertext2);
    }

    #[test]
    fn test_ciphertext_encode_decode() {
        let rng_sk = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut sk = [0u8; 32];
        rng_sk.fill_bytes(&mut sk[..]);
        let sk_fs = Fs::to_uniform(elgamal::elgamal_extend(&sk).as_bytes()).into_repr();

        let rng_r = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);
        let mut randomness = [0u8; 32];
        rng_r.fill_bytes(&mut randomness[..]);
        let r_fs = Fs::to_uniform(elgamal::elgamal_extend(&randomness).as_bytes());

        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let value: u32 = 5 as u32;

        let ciphertext1 = elgamal::Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);
        let ciphertext_b = Ciphertext::from_ciphertext(&ciphertext1);

        let encoded_cipher = ciphertext_b.encode();

        let decoded_cipher = Ciphertext::decode(&mut encoded_cipher.as_slice()).unwrap();
        assert_eq!(ciphertext_b, decoded_cipher);
    }

    #[test]
    fn test_ciphertext_rw() {
        let params = &JubjubBls12::new();
        let p_g = FixedGenerators::Diversifier;

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let sk_fs = Fs::rand(rng);
        let r_fs = Fs::rand(rng);

        let public_key = EncryptionKey(params.generator(p_g).mul(sk_fs, params));
        let value = 10 as u32;

        let ciphertext = elgamal::Ciphertext::encrypt(value, r_fs, &public_key, p_g, params);

        let mut buf = [0u8; 64];
        ciphertext.write(&mut &mut buf[..]).unwrap();

        let ciphertext_a = Ciphertext(buf.to_vec());
        let ciphertext_b = Ciphertext::from_ciphertext(&ciphertext);

        assert_eq!(ciphertext_a, ciphertext_b);
    }
}

