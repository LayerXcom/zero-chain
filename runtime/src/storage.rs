use super::state::{CommittedBalanceMap, TxoMap};
use proofs::primitives::{PaymentAddress};
use pairing::bls12_381::Bls12;

storage_items! {
    pub CommittedBalance: b"sys:commitedbalance" 
        => default map [ PaymentAddress<Bls12> => CommittedBalanceMap<Bls12> ];
    pub Txo: b"sys:txo" 
        => default map [ PaymentAddress<Bls12> => TxoMap<Bls12>];
}
