extern crate cfg_if;
extern crate wasm_bindgen;

mod utils;

use cfg_if::cfg_if;
use wasm_bindgen::prelude::*;

use rand::{ChaChaRng, SeedableRng, Rng};
use zprimitives::{
    pkd_address::PkdAddress,
    signature::RedjubjubSignature,
    keys
    };
use zpairing::{
    bls12_381::Bls12,
    Field,
};
use zjubjub::{
    curve::{JubjubBls12, FixedGenerators, JubjubParams},
    redjubjub::{h_star, Signature, write_scalar},
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

#[wasm_bindgen]
pub fn gen_account_id(sk: &[u8]) -> JsValue {
    let params = &JubjubBls12::new();
    let exps = keys::ExpandedSpendingKey::<Bls12>::from_spending_key(sk);


    let viewing_key = keys::ViewingKey::<Bls12>::from_expanded_spending_key(&exps, params);
    let address = viewing_key.into_payment_address(params);

    let pkd_address = PkdAddress::from_payment_address(&address);
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
    let sig = RedjubjubSignature::from_signature(&sig);
    JsValue::from_serde(&sig).expect("fails to write json")
}
