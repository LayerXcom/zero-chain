use pairing::{
    PrimeField,
    PrimeFieldRepr,
    Field,    
};

use scrypto::jubjub::{
    JubjubEngine,
    JubjubParams,
    edwards,
    PrimeOrder,
    FixedGenerators,
    ToUniform,
    Unknown,
};
use rand::{OsRng, Rng};
use zcrypto::constants::{
        PLAINTEXT_SIZE, 
        CIPHERTEXT_SIZE, 
        KDF_PERSONALIZATION
};
use blake2_rfc::blake2s::Blake2s;
// Temporary use for enc/dec
use pcrypto::aes::{
    encrypt_128_ctr, 
    decrypt_128_ctr
};
use proofs::primitives::{Diversifier, ValueCommitment};
use byteorder::{
    LittleEndian,
    WriteBytesExt
};

pub struct Commitments<E: JubjubEngine> (pub ValueCommitment<E>);

impl<E: JubjubEngine> Commitments<E> {    
    pub fn new (
        value: u64,
        randomness: E::Fs,
        is_negative: bool
    ) -> Self 
    {
        Commitments (
            ValueCommitment {
                value,
                randomness,
                is_negative
            }
        )
    }   

    pub fn encrypt_cm_to_recipient(
        &self,
        pk_d: &edwards::Point<E, PrimeOrder>,         
        diversifier: &Diversifier,
        params: &E::Params
    ) -> Ciphertext<E>
    {
        let mut rng = OsRng::new().expect("should be able to construct RNG"); // TODO: replace OsRng
        let mut buffer = [0u8; 64];

        for i in 0..buffer.len() {
            buffer[i] = rng.gen();
        }
        // Generate uniformed random value as ephemeral secret key
        let esk = E::Fs::to_uniform(&buffer[..]);

        // let p = pk_d.mul_by_cofactor(params); // needs lazy_static for params(JUBJUB)?
        // Generate shared secret
        let shared_secret = pk_d.mul(esk, params);

        // Derive ephemeral public key
        let g_d = diversifier.g_d::<E>(params).unwrap();
        let epk = g_d.mul(esk, params);

        let mut preimage = [0; 64];
        shared_secret.write(&mut preimage[0..32]);
        epk.write(&mut preimage[32..64]);

        let mut h = Blake2s::with_params(32, &[], &[], KDF_PERSONALIZATION);
        h.update(&preimage);
        let h = h.finalize();
        
        let mut ciphertext_bytes = [0; CIPHERTEXT_SIZE];
        let iv: [u8; 16] = rng.gen();

        let mut plaintext = vec![];
        // TODO: Ensure the byteorder is correct
        (&mut plaintext).write_u64::<LittleEndian>(self.0.value).unwrap();
        self.0.randomness.into_repr().write_le(&mut plaintext).unwrap();        

        encrypt_128_ctr(&h.as_ref()[0..16], &iv, &plaintext, &mut ciphertext_bytes)
            .expect("input lengths of key and iv are both 16; qed");

        Ciphertext {
            encrypted_commitment: ciphertext_bytes,
            epk: epk
        }
    }
}

// #[derive(Clone, Encode, Decode)]
// pub struct EncryptedCommitment([u8; CIPHERTEXT_SIZE]);

#[derive(Clone, Encode, Decode, Default)]
pub struct Ciphertext<E: JubjubEngine> {
    encrypted_commitment: [u8; CIPHERTEXT_SIZE],    
    epk: edwards::Point<E, PrimeOrder>,
}

// impl<E: JubjubEngine> Ciphertext<E> {
//     pub fn decrypt(
//         &self,
//         params: &E::Params
//     ) -> Commitments 
//     {

//     }
// }
