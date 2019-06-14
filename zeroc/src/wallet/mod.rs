

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalletName(String);

pub struct Wallet {

    pub name: WalletName,
}