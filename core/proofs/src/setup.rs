use pairing::bls12_381::Bls12;
use bellman::groth16::{
    generate_random_parameters,
    prepare_verifying_key,
};
use rand::Rng;
use crate::circuit::ConfidentialTransfer;
use crate::PARAMS;
use crate::confidential::KeyContext;

pub fn confidential_setup<R: Rng>(rng: &mut R) -> KeyContext<Bls12> {
    // Create parameters for the confidential transfer circuit
    let proving_key = {
        let c = ConfidentialTransfer::<Bls12> {
            params: &PARAMS,
            amount: None,
            remaining_balance: None,
            randomness: None,
            alpha: None,
            proof_generation_key: None,
            dec_key_sender: None,
            enc_key_recipient: None,
            encrypted_balance: None,
            fee: None,
            g_epoch: None,
        };

        generate_random_parameters(c, rng).unwrap()
    };

    let prepared_vk = prepare_verifying_key(&proving_key.vk);
    let mut v = vec![];
    prepared_vk.write(&mut &mut v).unwrap();
    println!("pvk: {:?}", v.len());

    KeyContext::new(proving_key, prepared_vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, XorShiftRng};
    use bellman::groth16::PreparedVerifyingKey;

    #[test]
    fn test_preparedvk_rw() {
        let rng = &mut XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let key_context = confidential_setup(rng);
        let mut v = vec![];
        key_context.vk().write(&mut &mut v).unwrap();

        let prepared_vk_a = PreparedVerifyingKey::<Bls12>::read(&mut &v[..]).unwrap();

        let mut buf = vec![];
        prepared_vk_a.write(&mut &mut buf).unwrap();

        let prepared_vk_b = PreparedVerifyingKey::<Bls12>::read(&mut &buf[..]).unwrap();

        assert_eq!(prepared_vk_a, prepared_vk_b);
    }
}
