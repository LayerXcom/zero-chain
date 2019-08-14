

// pub struct AnonymousProof<E: JubjubEngine> {
//     proof: Proof<E>,
//     rvk: PublicKey<E>,
//     enc_key_sender: EncryptionKey<E>,
//     enc_keys: MultiEncKeys<E>,
//     multi_ciphertexts: MultiCiphertexts<E>,
//     cipher_balance: Ciphertext<E>,
// }

// impl<E: JubjubEngine> AnonymousProof<E> {
//     pub fn gen_proof<R: Rng>(
//         amount: u32,
//         remaining_balance: u32,
//         fee: u32,
//         alpha: E::Fs,
//         proving_key: &Parameters<E>,
//         prepared_vk: &PreparedVerifyingKey<E>,
//         proof_generation_key: &ProofGenerationKey<E>,
//         enc_keys: &MultiEncKeys<E>,
//         cipher_balance: Ciphertext<E>,
//         g_epoch: &edwards::Point<E, PrimeOrder>,
//         rng: &mut R,
//         params: &E::Params,
//     ) -> Result<Self, SynthesisError>
//     {

//         unimplemented!();
//     }
// }
