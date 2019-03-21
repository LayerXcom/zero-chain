extern crate cfg_if;
#[macro_use]
extern crate serde_derive;

mod utils;
use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

use rand::{ChaChaRng, SeedableRng, Rng, Rand};
use keys;
use zpairing::{
    bls12_381::Bls12 as zBls12,
    Field as zField, PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr,
};
use pairing::{
    bls12_381::Bls12, Field
};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, 
        FixedGenerators as zFixedGenerators, 
        JubjubParams as zJubjubParams, 
        edwards::Point as zPoint,
        fs::Fs as zFs
        },
    redjubjub::{h_star as zh_star, 
                Signature as zSignature, 
                PublicKey as zPublicKey, 
                write_scalar as zwrite_scalar, 
                read_scalar as zread_scalar},
};
use scrypto::{
    jubjub::{fs::Fs, FixedGenerators, JubjubBls12, JubjubParams},    
};
use proofs::{
    primitives::{ExpandedSpendingKey, ViewingKey, PaymentAddress},
    elgamal::Ciphertext,
};
use bellman::groth16::{Parameters, PreparedVerifyingKey};
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
pub struct PkdAddress(pub Vec<u8>);

#[wasm_bindgen]
pub fn gen_account_id(sk: &[u8]) -> JsValue {
    let params = &zJubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&exps, params);
    let address = viewing_key.into_payment_address(params);

    let mut v = [0u8; 32];
    address.write(&mut v[..]).expect("fails to write payment address");    

    let pkd_address = PkdAddress(v.to_vec());
    JsValue::from_serde(&pkd_address).expect("fails to write json")
}

#[derive(Serialize, Deserialize)]
pub struct Ivk(pub Vec<u8>);

#[wasm_bindgen]
pub fn gen_ivk(sk: &[u8]) -> Vec<u8> {
    let params = &zJubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&exps, params);
    let ivk = viewing_key.ivk();

    let mut buf = vec![];
    ivk.into_repr().write_le(&mut buf).unwrap();    

    buf    
}

#[wasm_bindgen]
pub fn gen_rsk(sk: &[u8]) -> Vec<u8> {    
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let mut buf = vec![];
    exps.ask.into_repr().write_le(&mut buf).unwrap();

    buf
}

#[wasm_bindgen]
pub fn gen_rvk(sk: &[u8]) -> Vec<u8> {
    let params = &zJubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<zBls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<zBls12>::from_expanded_spending_key(&exps, params);

    let mut buf = vec![];
    viewing_key.ak.write(&mut buf).unwrap();

    buf
}

#[wasm_bindgen]
pub fn sign(mut sk: &[u8], msg: &[u8], seed_slice: &[u32]) -> Vec<u8> {
    let params = &zJubjubBls12::new();
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let p_g = zFixedGenerators::Diversifier;
    
    let mut ask_repr = zFs::default().into_repr();    
    ask_repr.read_le(&mut sk).unwrap();       
    let ask = zFs::from_repr(ask_repr).unwrap();

    // T = (l_H + 128) bits of randomness
    // For H*, l_H = 512 bits
    let mut t = [0u8; 80];
    rng.fill_bytes(&mut t[..]);

    // r = H*(T || M)
    let r = zh_star::<zBls12>(&t[..], msg);

    // R = r . P_G
    let r_g = params.generator(p_g).mul(r, params);
    let mut rbar = [0u8; 32];
    r_g.write(&mut &mut rbar[..])
        .expect("Jubjub points should serialize to 32 bytes");

    // S = r + H*(Rbar || M) . sk
    let mut s = zh_star::<zBls12>(&rbar[..], msg);
    s.mul_assign(&ask);
    s.add_assign(&r);
    let mut sbar = [0u8; 32];
    zwrite_scalar::<zBls12, &mut [u8]>(&s, &mut sbar[..])
        .expect("Jubjub scalars should serialize to 32 bytes");    

    let sig = zSignature { rbar, sbar };     

    let mut writer = [0u8; 64];
    sig.write(&mut writer[..]).expect("fails to write signature");
  
    writer.to_vec()    
}

#[wasm_bindgen]
pub fn verify(mut vk: &[u8], msg: &[u8], mut sig: &[u8]) -> bool {
    let params = &zJubjubBls12::new();    
    let p_g = zFixedGenerators::Diversifier;

    let vk = zPublicKey::<zBls12>::read(&mut vk, params).unwrap();
    let sig = zSignature::read(&mut sig).unwrap();

    // c = H*(Rbar || M)
    let c = zh_star::<zBls12>(&sig.rbar[..], msg);

    // Signature checks:
    // R != invalid
    let r = match zPoint::read(&mut &sig.rbar[..], params) {
        Ok(r) => r,
        Err(_) => return false,
    };
    // S < order(G)
    // (E::Fs guarantees its representation is in the field)
    let s = match zread_scalar::<zBls12, &[u8]>(&sig.sbar[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 0 = h_G(-S . P_G + R + c . vk)
    vk.0.mul(c, params).add(&r, params).add(
        &params.generator(p_g).mul(s, params).negate().into(),
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
    mut prepared_vk: &[u8],
    seed_slice: &[u32],
) -> JsValue
{
    let params = &JubjubBls12::new();
    let mut rng = &mut ChaChaRng::from_seed(seed_slice);
    let p_g = FixedGenerators::NoteCommitmentRandomness; // 1
    let remaining_balance = balance - value;

    // let alpha = Fs::rand(&mut rng);
    let alpha = Fs::zero();

    let ex_sk_s = ExpandedSpendingKey::<Bls12>::from_spending_key(&sk[..]);
    let viewing_key_s = ViewingKey::<Bls12>::from_expanded_spending_key(&ex_sk_s, &params);
    let ivk = viewing_key_s.ivk();    
    
    let r_fs = Fs::rand(&mut rng);
    let public_key = params.generator(p_g).mul(ivk, &params).into();
    let ciphertext_balance = Ciphertext::encrypt(balance, r_fs, &public_key, p_g, &params);

    let address_recipient = PaymentAddress::<Bls12>::read(&mut address_recipient, params).unwrap();
    let proving_key = Parameters::<Bls12>::read(&mut proving_key, true).unwrap();
    let prepared_vk = PreparedVerifyingKey::<Bls12>::read(&mut prepared_vk).unwrap();

    let tx = Transaction::gen_tx(
                value, 
                remaining_balance, 
                alpha,
                &proving_key,
                &prepared_vk,
                &address_recipient,
                &ex_sk_s,
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
    // JsValue::from_str("Hey")
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::XorShiftRng;
    use scrypto::jubjub::{fs::Fs, ToUniform};
    use pairing::{PrimeField, PrimeFieldRepr, Field};
    use zjubjub::redjubjub::PrivateKey as zPrivateKey;
    use scrypto::redjubjub::{PrivateKey, PublicKey};      

    fn get_pk_and_vk() -> (Vec<u8>, Vec<u8>) {
        let pk_path = Path::new("../cli/proving.params");        
        let vk_path = Path::new("../cli/verification.params");        

        let pk_file = File::open(&pk_path).unwrap();
        let vk_file = File::open(&vk_path).unwrap();

        let mut pk_reader = BufReader::new(pk_file);
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_pk = vec![];
        pk_reader.read_to_end(&mut buf_pk).unwrap();

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        (buf_pk, buf_vk)
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
}
