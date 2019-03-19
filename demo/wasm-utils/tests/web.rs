//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use zerochain_wasm_utils::{decrypt_ca, gen_account_id, gen_ivk, sign, verify, gen_call};
use rand::{SeedableRng, Rng, Rand, XorShiftRng};
use keys;
use zpairing::{
    bls12_381::Bls12 as zBls12,
    PrimeField as zPrimeField, PrimeFieldRepr as zPrimeFieldRepr,
};
use pairing::{PrimeField, PrimeFieldRepr, bls12_381::Bls12};
use zjubjub::{
    curve::{JubjubBls12 as zJubjubBls12, 
        FixedGenerators as zFixedGenerators,                 
        fs::Fs as zFs
        },
    redjubjub::{PublicKey as zPublicKey, PrivateKey as zPrivateKey},
};
use zcrypto::elgamal::Ciphertext as zCiphertext;
use bellman::groth16::{Parameters, PreparedVerifyingKey};
use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read};  
#[macro_use]
extern crate hex_literal;
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref PROVINGKEY: Vec<u8> = {
        use std::path::Path;
use std::fs::File;
use std::io::{BufReader, Read};  
        let pk_path = Path::new("../cli/proving.params");                      
        let pk_file = File::open(&pk_path).unwrap();        
        let mut pk_reader = BufReader::new(pk_file);        

        let mut buf_pk = vec![];
        pk_reader.read_to_end(&mut buf_pk).unwrap();
        
        buf_pk
    };

    static ref VERIFYINGKEY: Vec<u8> = {
        let vk_path = Path::new("../cli/verification.params");  
        let vk_file = File::open(&vk_path).unwrap();
        let mut vk_reader = BufReader::new(vk_file);

        let mut buf_vk = vec![];
        vk_reader.read_to_end(&mut buf_vk).unwrap();

        buf_vk
    };
}

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_get_account_id() {
    let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
    let sk: [u8; 32] = rng.gen();

    let account_id = gen_account_id(&sk);
}

#[wasm_bindgen_test]
fn test_decrypt() {    
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

    let res = decrypt_ca(&v[..], &buf[..]).unwrap(); 
    assert_eq!(value, res);
}

#[wasm_bindgen_test]
fn test_sign_verify() {
    let rsk: [u8; 32] = hex!("dcfd7a3cb8291764a4e1ab41f6831d2e285a98114cdc4a2d361a380de0e3cb07");
    let rvk: [u8; 32] = hex!("791b91fae07feada7b6f6042b1e214bc75759b3921956053936c38a95271a834");
    
    let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
    let msg = b"Foo bar";
    let seed_slice: [u32; 8] = rng.gen();

    let params = &zJubjubBls12::new();   
    let p_g = zFixedGenerators::Diversifier;        

    let sig = sign(&rsk, msg, &seed_slice);

    let is_valid = verify(&rvk, msg, &sig[..]);

    assert!(is_valid);
}

#[wasm_bindgen_test]
fn test_gen_call() {
    let rng = &mut XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);
    let balance = 100 as u32;
    let amount = 10 as u32;

    let alice_seed = b"Alice                           ";
    let address_recipient: [u8; 32] = hex!("a23bb484f72b28a4179a71057c4528648dfb37974ccd84b38aa3e342f9598515");
    let random_seed: [u32; 8] = rng.gen();        

    let call = gen_call(
            alice_seed, 
            &address_recipient[..], 
            amount, 
            balance, 
            &PROVINGKEY[..], 
            &VERIFYINGKEY[..], 
            &random_seed[..]
        );
}
