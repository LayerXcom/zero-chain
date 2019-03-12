extern crate cfg_if;
#[macro_use]
extern crate serde_derive;

mod utils;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

use rand::{ChaChaRng, SeedableRng, Rng};
use keys::{self, PaymentAddress};
use zpairing::{
    bls12_381::Bls12,
    Field,
};
use zjubjub::{
    curve::{JubjubBls12, FixedGenerators, JubjubParams, edwards::Point},
    redjubjub::{h_star, Signature, PublicKey, write_scalar, read_scalar},
};

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, wasm-utils!");
}

#[derive(Serialize)]
pub struct PkdAddress(pub(crate) [u8; 32]);

impl From<PaymentAddress<Bls12>> for PkdAddress {
    fn from(address: PaymentAddress<Bls12>) -> Self {
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
    let params = &JubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<Bls12>::from_spending_key(sk);

    let viewing_key = keys::ViewingKey::<Bls12>::from_expanded_spending_key(&exps, params);
    let address = viewing_key.into_payment_address(params);

    let pkd_address = PkdAddress::from(address);
    JsValue::from_serde(&pkd_address).expect("fails to write json")
}

#[wasm_bindgen]
pub fn sign(sk: &[u8], msg: &[u8], seed_slice: &[u32]) -> JsValue {
    let params = &JubjubBls12::new();
    let rng = &mut ChaChaRng::from_seed(seed_slice);
    let g = params.generator(FixedGenerators::SpendingKeyGenerator);

    let exps = keys::ExpandedSpendingKey::<Bls12>::from_spending_key(sk);

    // T = (l_H + 128) bits of randomness
    // For H*, l_H = 512 bits
    let mut t = [0u8; 80];
    rng.fill_bytes(&mut t[..]);

    // r = H*(T || M)
    let r = h_star::<Bls12>(&t[..], msg);

    // R = r . P_G
    let r_g = g.mul(r, params);
    let mut rbar = [0u8; 32];
    r_g.write(&mut &mut rbar[..])
        .expect("Jubjub points should serialize to 32 bytes");

    // S = r + H*(Rbar || M) . sk
    let mut s = h_star::<Bls12>(&rbar[..], msg);
    s.mul_assign(&exps.ask);
    s.add_assign(&r);
    let mut sbar = [0u8; 32];
    write_scalar::<Bls12, &mut [u8]>(&s, &mut sbar[..])
        .expect("Jubjub scalars should serialize to 32 bytes");

    let sig = Signature { rbar, sbar };
    let sig = RedjubjubSignature::from(sig);
    JsValue::from_serde(&sig).expect("fails to write json")
}

#[wasm_bindgen]
pub fn verify(vk: Vec<u8>, msg: &[u8], sig: Vec<u8>) -> bool {
    let params = &JubjubBls12::new();    

    let vk = PublicKey::<Bls12>::read(&mut &vk[..], params).unwrap();
    let sig = Signature::read(&mut &sig[..]).unwrap();

    // c = H*(Rbar || M)
    let c = h_star::<Bls12>(&sig.rbar[..], msg);

    // Signature checks:
    // R != invalid
    let r = match Point::read(&mut &sig.rbar[..], params) {
        Ok(r) => r,
        Err(_) => return false,
    };
    // S < order(G)
    // (E::Fs guarantees its representation is in the field)
    let s = match read_scalar::<Bls12, &[u8]>(&sig.sbar[..]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // 0 = h_G(-S . P_G + R + c . vk)
    vk.0.mul(c, params).add(&r, params).add(
        &params.generator(FixedGenerators::SpendingKeyGenerator)
                .mul(s, params)
                .negate()
                .into(),
        params
    ).mul_by_cofactor(params).eq(&Point::zero())
}



// #[derive(Serialize)]
// struct Calls {

// }

// #[wasm_bindgen]
// pub fn gen_call(sk: &[u8], index: u64, address_recipient: &[u8], value: u32, balance: u32) -> JsValue {
//     let params = &JubjubBls12::new();
//     let rng = &mut ChaChaRng::from_seed(seed_slice);
//     let p_g = params.generator(FixedGenerators::NullifierPosition); // 2


// }

