use scrypto::jubjub::{
    JubjubEngine,
    JubjubParams,
    edwards,
    PrimeOrder,
    FixedGenerators
};

use rand::{OsRng, Rng};

use z_constants;

use blake2_rfc::blake2s::Blake2s;

use primitives;


pub struct Note<E: JubjubEngine> {
    pub value: u64,
    // The commitment randomness
    pub r: E::Fs,
}

pub struct SerializedNote(&[u8; z_constants::PLAINTEXT_SIZE]);

impl<E: JubjubEngine> SerializedNote<E> {
    pub fn encrypt_note_to_recipient(
        &self,
        pk_d: edwards::Point<E, PrimeOrder>,         
        diversifier: Diversifier,
        params: &E::Params
    ) -> SerializedEncNote
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
        shared_secret.write(&mut preimage[0..32].unwrap());
        self.nk.write(&mut preimage[32..64].unwrap());

        let mut h = Blake2s::with_params(32, &[], &[], z_constants::KDF_PERSONALIZATION);
        h.update(&preimage);
        let mut h = h.finalize().as_ref().to_vec();
        


    }
}


pub struct EncryptedNote<E: JubjubEngine> {
    pub cipher_text: Vec<u8>,
    pub epk: 
}

pub struct SerializedEncNote(&[u8; z_constants::CIPHERTEXT_SIZE]);

impl<E: JubjubEngine> SerializedEncNote<E> {
    pub fn 
}
