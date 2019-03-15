extern crate cfg_if;
#[macro_use]
extern crate serde_derive;
extern crate parity_codec as codec;
#[macro_use]
extern crate parity_codec_derive as codec_derive;
#[macro_use]
extern crate hex_literal;

mod utils;
use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

use rand::{ChaChaRng, SeedableRng, Rng, Rand};
use keys;
use zpairing::{
    bls12_381::Bls12 as zBls12,
    Field, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr,
};
use pairing::{
    bls12_381::Bls12, PrimeField
};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, 
        FixedGenerators as zFixedGenerators, 
        JubjubParams as zJubjubParams, 
        edwards::Point as zPoint,
        fs::Fs as zFs
        },
    redjubjub::{h_star, Signature, PublicKey, write_scalar, read_scalar},
};
use scrypto::jubjub::{fs, FixedGenerators, ToUniform, JubjubBls12, JubjubParams};
use proofs::{
    primitives::{ExpandedSpendingKey, ViewingKey, PaymentAddress},
    elgamal::{Ciphertext, elgamal_extend},
};
use bellman::groth16::Parameters;
use zcrypto::elgamal::Ciphertext as zCiphertext;

pub mod transaction;
use transaction::Transaction;

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[derive(Serialize)]
pub struct PkdAddress(pub(crate) [u8; 32]);

impl From<keys::PaymentAddress<zBls12>> for PkdAddress {
    fn from(address: keys::PaymentAddress<zBls12>) -> Self {
        let mut writer = [0u8; 32];
        address.write(&mut writer[..]).expect("fails to write payment address");
        PkdAddress(writer)
    }
}

#[derive(Serialize)]
pub struct RedjubjubSignature(pub(crate) Vec<u8>);

impl From<Signature> for RedjubjubSignature {
    fn from(sig: Signature) -> Self {
        let mut writer = [0u8; 64];
        sig.write(&mut writer[..]).expect("fails to write signature");
        RedjubjubSignature(writer.to_vec())
    }
}

#[wasm_bindgen]
pub fn gen_account_id(sk: &[u8]) -> JsValue {
    let params = &zJubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&exps, params);
    let address = viewing_key.into_payment_address(params);

    let pkd_address = PkdAddress::from(address);
    JsValue::from_serde(&pkd_address).expect("fails to write json")
}

#[derive(Serialize)]
pub struct Ivk(pub(crate) Vec<u8>);

#[wasm_bindgen]
pub fn gen_ivk(sk: &[u8]) -> JsValue {
    let params = &zJubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&exps, params);
    let ivk = viewing_key.ivk();

    let mut buf = vec![];
    ivk.into_repr().write_le(&mut buf).unwrap();    
    let ivk = Ivk(buf);
    JsValue::from_serde(&ivk).expect("fails to write json")
}

#[wasm_bindgen]
pub fn sign(sk: &[u8], msg: &[u8], seed_slice: &[u32]) -> JsValue {
    let params = &zJubjubBls12::new();
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let g = params.generator(zFixedGenerators::Diversifier);

    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    // T = (l_H + 128) bits of randomness
    // For H*, l_H = 512 bits
    let mut t = [0u8; 80];
    rng.fill_bytes(&mut t[..]);

    // r = H*(T || M)
    let r = h_star::<zBls12>(&t[..], msg);

    // R = r . P_G
    let r_g = g.mul(r, params);
    let mut rbar = [0u8; 32];
    r_g.write(&mut &mut rbar[..])
        .expect("Jubjub points should serialize to 32 bytes");

    // S = r + H*(Rbar || M) . sk
    let mut s = h_star::<zBls12>(&rbar[..], msg);
    s.mul_assign(&exps.ask);
    s.add_assign(&r);
    let mut sbar = [0u8; 32];
    write_scalar::<zBls12, &mut [u8]>(&s, &mut sbar[..])
        .expect("Jubjub scalars should serialize to 32 bytes");

    let sig = Signature { rbar, sbar };
    let sig = RedjubjubSignature::from(sig);
    JsValue::from_serde(&sig).expect("fails to write json")
}

#[wasm_bindgen]
pub fn verify(vk: Vec<u8>, msg: &[u8], sig: Vec<u8>) -> bool {
    let params = &zJubjubBls12::new();    

    let vk = PublicKey::<zBls12>::read(&mut &vk[..], params).unwrap();
    let sig = Signature::read(&mut &sig[..]).unwrap();

    // c = H*(Rbar || M)
    let c = h_star::<zBls12>(&sig.rbar[..], msg);

    // Signature checks:
    // R != invalid
    let r = match zPoint::read(&mut &sig.rbar[..], params) {
        Ok(r) => r,
        Err(_) => return false,
    };
    // S < order(G)
    // (E::Fs guarantees its representation is in the field)
    let s = match read_scalar::<zBls12, &[u8]>(&sig.sbar[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 0 = h_G(-S . P_G + R + c . vk)
    vk.0.mul(c, params).add(&r, params).add(
        &params.generator(zFixedGenerators::Diversifier)
                .mul(s, params)
                .negate()
                .into(),
        params
    ).mul_by_cofactor(params).eq(&zPoint::zero())
}

#[derive(Serialize)]
struct Calls {
    zk_proof: Vec<u8>,
    address_sender: Vec<u8>,
    address_recipient: Vec<u8>,
    value_sender: Vec<u8>,
    value_recipient: Vec<u8>,
    balance_sender: Vec<u8>,
    rk: Vec<u8>,
    rsk: Vec<u8>,
}

#[wasm_bindgen]
pub fn gen_call(
    sk: &[u8],    
    mut address_recipient: &[u8], 
    value: u32, 
    balance: u32,
    mut proving_key: &[u8],
    seed_slice: &[u32],
) -> JsValue 
{
    let params = &JubjubBls12::new();
    let mut rng = &mut ChaChaRng::from_seed(seed_slice);
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
    let remaining_balance = balance - value;

    let alpha = fs::Fs::rand(&mut rng);

    let ex_sk_s = ExpandedSpendingKey::<Bls12>::from_spending_key(&sk[..]);
    let viewing_key_s = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_s, &params);
    let ivk = viewing_key_s.ivk();
    let mut randomness = [0u8; 32];

    rng.fill_bytes(&mut randomness[..]);
    let r_fs = fs::Fs::to_uniform(elgamal_extend(&randomness).as_bytes());
    let public_key = params.generator(p_g).mul(ivk, &params).into();
    let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, &params);

    let address_recipient = PaymentAddress::<Bls12>::read(&mut address_recipient, params).unwrap();
    let proving_key = Parameters::<Bls12>::read(&mut proving_key, true).unwrap();

    let tx = Transaction::gen_tx(
                value, 
                remaining_balance, 
                alpha,
                &proving_key,
                // &prepared_vk,
                &address_recipient,
                sk,
                ciphertext_balance,                        
                rng
        ).expect("fails to generate the tx");    
    
    let calls = Calls {
        zk_proof: tx.proof.to_vec(),
        address_sender: tx.address_sender.to_vec(),
        address_recipient: tx.address_recipient.to_vec(),
        value_sender: tx.enc_val_sender.to_vec(),
        value_recipient: tx.enc_val_recipient.to_vec(),
        balance_sender: tx.enc_bal_sender.to_vec(),
        rk: tx.rk.to_vec(),
        rsk: tx.rsk.to_vec(),
    };

    JsValue::from_serde(&calls).expect("fails to write json")
}

#[wasm_bindgen(catch)]
pub fn decrypt_ca(mut ciphertext: &[u8], mut sk: &[u8]) -> Result<u32, JsValue> {
    let params = &zJubjubBls12::new();
    let p_g = zFixedGenerators::Diversifier;

    let ciphertext = zCiphertext::<zBls12>::read(&mut ciphertext, params).unwrap();
    let mut sk_repr = zFs::default().into_repr();    
    sk_repr.read_le(&mut sk).unwrap();    

    match ciphertext.decrypt(zFs::from_repr(sk_repr).unwrap(), p_g, params) {
        Some(v) => Ok(v),
        None => {            
            Err(JsValue::from_str("fails to decrypt"))
        }
    }
}

// #[wasm_bindgen]
// pub fn decrypt(mut ciphertext: &[u8], sk: &[u8]) -> JsValue {
//     let params = &zJubjubBls12::new();
//     let p_g = zFixedGenerators::ElGamal;

//     let ciphertext = zCiphertext::<zBls12>::read(&mut ciphertext, params).unwrap();
//     // let mut sk_repr = Fs::Repr::default();
//     // sk_repr.read_le(&mut )
//     JsValue::from_serde(&ciphertext.decrypt(sk, p_g, params).unwrap()).expect("fails to write json")
// }

#[cfg(test)]
mod tests {
    use super::*;
    use rand::XorShiftRng;
    use scrypto::jubjub::{fs::Fs, ToUniform};
    use pairing::{PrimeField, PrimeFieldRepr, Field};
    use zjubjub::redjubjub::PrivateKey as zPrivateKey;
    use scrypto::redjubjub::{PrivateKey, PublicKey};

    #[test]
    fn test_decrypt() {
        let v2: [u8; 64] = hex!("858220efbf556a23d7b8c1dc9e5b9cc8fac114a761b2ae502314b2cb21653b3c22f25054a1fb20c2c3e41a4da141c2a8dca612519009265dcaee3bb04e93b8e6");        
        let buf2: [u8; 32] = hex!("1e3eee98dbb517f8452e88d84cc7119c0094699cfca8196f1521e33155622f04");       

        let alice_seed = b"Alice                           ";
        let params = &zJubjubBls12::new();
        let p_g = zFixedGenerators::Diversifier;

        let expsk = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(alice_seed);        
        let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&expsk, params);    
        let ivk = viewing_key.ivk();        
        
        let mut buf = vec![];
        ivk.into_repr().write_le(&mut &mut buf).unwrap(); 	

        let rng = &mut XorShiftRng::from_seed([0xbc4f6d47, 0xd62f276d, 0xb963afd3, 0x54558639]);    
        let r_fs = zFs::rand(rng);

        let value: u32 = 6 as u32;        
        let address = viewing_key.into_payment_address(params);	 

        let ciphetext = zCiphertext::encrypt(value, r_fs, &address.0, p_g, params);

        let mut v = vec![];
        ciphetext.write(&mut v).unwrap(); 

        let res = decrypt_ca(&v2[..], &buf2[..]).unwrap();
        println!("res:{}", res);
    }

    #[test]
    fn test_fs_write_read() {
        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let fs = zFs::rand(rng);
        let mut buf = vec![];
        fs.into_repr().write_le(&mut &mut buf).unwrap();

        let mut sk_repr = zFs::default().into_repr();
        sk_repr.read_le(&mut &buf[..]).unwrap();

        assert_eq!(fs, zFs::from_repr(sk_repr).unwrap());
    }

    #[test]
    fn test_sign_verify() {
        let rsk: [u8; 32] = hex!("dcfd7a3cb8291764a4e1ab41f6831d2e285a98114cdc4a2d361a380de0e3cb07");
        let rvk: [u8; 32] = hex!("d05a2394f5e5e3950ccd804c2bc31302d57c1ff07615f971a2d379c5aadfbe4b");

        let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
        let msg: [u8; 32] = rng.gen();
        let seed_slice: [u32; 8] = rng.gen();

        let params = &JubjubBls12::new();    
        let p_g = FixedGenerators::NoteCommitmentRandomness;

        // let alpha = Fs::zero();
        // let sk = PrivateKey::<Bls12>(rng.gen());
        // let vk = PublicKey::from_private(&sk, p_g, params);

        // let rsk = sk.randomize(alpha);
        // let rvk = vk.randomize(alpha, p_g, params);
        
        // let sig = rsk.sign(&msg, rng, p_g, params);
        // let isValid = rvk.verify(&msg, &sig, p_g, params);

        let private_key = PrivateKey::<Bls12>::read(&mut &rsk[..]).unwrap();
        let sig = private_key.sign(&msg, rng, p_g, params);

        let public_key = PublicKey::<Bls12>::read(&mut &rvk[..], params).unwrap();
        let isValid = public_key.verify(&msg, &sig, p_g, params);

        // println!("rng:{:?}", msg);

        // let sig = sign(&rsk[..], &msg[..], &seed_slice[..]);
        // let isValid = verify(rvk.to_vec(), &msg, sig.into_serde().unwrap());
        assert!(isValid);
    }
}
