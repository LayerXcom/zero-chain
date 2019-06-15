use keys::

#[derive(Clone, Copy, Debug, PartialEq)]
struct ChainCode([u8; 32]);

pub struct ExtendedSpendingKey<K> {
    pub key: ,
    pub chaincode: ChainCode,
}

