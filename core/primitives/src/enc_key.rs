use keys::EncryptionKey;
use fixed_hash::construct_fixed_hash;
use pairing::bls12_381::{Bls12, Fr};
use pairing::io;
use crate::{PARAMS, IntoXY};
use core::convert::TryFrom;

const SIZE: usize = 32;

construct_fixed_hash! {
    pub struct EncKey(SIZE);
}

impl_fixed_hash_codec!(EncKey, SIZE);

impl TryFrom<EncryptionKey<Bls12>> for EncKey {
    type Error = io::Error;

    fn try_from(enc_key: EncryptionKey<Bls12>) -> Result<Self, io::Error> {
        let mut writer = [0u8; 32];
        enc_key.write(&mut writer[..])?;

        Ok(EncKey::from_slice(&writer))
    }
}

impl TryFrom<EncKey> for EncryptionKey<Bls12> {
    type Error = io::Error;

    fn try_from(enc_key: EncKey) -> Result<Self, io::Error> {
        EncryptionKey::<Bls12>::read(&mut &enc_key.0[..], &PARAMS)
    }
}

impl TryFrom<&EncKey> for EncryptionKey<Bls12> {
    type Error = io::Error;

    fn try_from(enc_key: &EncKey) -> Result<Self, io::Error> {
        EncryptionKey::<Bls12>::read(&mut &enc_key.0[..], &PARAMS)
    }
}

impl IntoXY<Bls12> for EncKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = EncryptionKey::<Bls12>::try_from(self)?
            .into_xy();

        Ok(point)
    }
}

impl IntoXY<Bls12> for &EncKey {
    fn into_xy(&self) -> Result<(Fr, Fr), io::Error> {
        let point = EncryptionKey::<Bls12>::try_from(**self)?
            .into_xy();

        Ok(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use core::convert::TryInto;

    #[test]
    fn test_addr_into_from() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let seed: [u8; 32] = rng.gen();

        let addr1 = EncryptionKey::<Bls12>::from_seed(&seed[..], &*PARAMS).unwrap();

        let account_id = EncKey::try_from(addr1.clone()).unwrap();
        let addr2 = account_id.try_into().unwrap();
        assert!(addr1 == addr2);
    }
}
