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
use zcrypto::constants::{PLAINTEXT_SIZE, CIPHERTEXT_SIZE, KDF_PERSONALIZATION};
use blake2_rfc::blake2s::Blake2s;
// Temporary use for enc/dec
use pcrypto::aes::{encrypt_128_ctr, decrypt_128_ctr};
use proofs::primitives::Diversifier;

pub struct SerializedCommitment<'a>(&'a [u8; PLAINTEXT_SIZE]);

impl<'a> SerializedCommitment<'a> {
    pub fn encrypt_cm_to_recipient<E: JubjubEngine>(
        &self,
        pk_d: edwards::Point<E, Unknown>,         
        diversifier: Diversifier,
        params: &'a E::Params
    ) -> EncryptedCommitment
    {
        let mut rng = OsRng::new().expect("should be able to construct RNG"); // TODO: replace OsRng
        let mut buffer = [0u8; 64];

        for i in 0..buffer.len() {
            buffer[i] = rng.gen();
        }
        // Generate uniformed random value as ephemeral secret key
        let esk = E::Fs::to_uniform(&buffer[..]);

        let p = pk_d.mul_by_cofactor(params); // needs lazy_static for params(JUBJUB)?
        // Generate shared secret
        let shared_secret = p.mul(esk, params);

        // Derive ephemeral public key
        let g_d = diversifier.g_d::<E>(params).unwrap();
        let epk = g_d.mul(esk, params);

        let mut preimage = [0; 64];
        shared_secret.write(&mut preimage[0..32]);
        epk.write(&mut preimage[32..64]);

        let mut h = Blake2s::with_params(32, &[], &[], KDF_PERSONALIZATION);
        h.update(&preimage);
        let h = h.finalize();
        
        let mut ciphertext = [0; CIPHERTEXT_SIZE];
        let iv: [u8; 16] = rng.gen();

        encrypt_128_ctr(&h.as_ref()[0..16], &iv, self.0, &mut ciphertext)
            .expect("input lengths of key and iv are both 16; qed");

        EncryptedCommitment(ciphertext)
    }
}

#[derive(Clone, Encode, Decode)]
pub struct EncryptedCommitment([u8; CIPHERTEXT_SIZE]);

impl Default for EncryptedCommitment {
    fn default() -> Self {
        EncryptedCommitment([0; CIPHERTEXT_SIZE])
    }
}

// impl<E: JubjubEngine> EncryptedCommitment<E> {
//     pub fn decrypt
// }
