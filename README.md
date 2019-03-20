# zero-chain
[![Build Status](https://travis-ci.com/LayerXcom/zero-chain.svg?branch=master)](https://travis-ci.com/LayerXcom/zero-chain)
[![Gitter](https://badges.gitter.im/LayerXcom/Zerochain.svg)](https://gitter.im/LayerXcom/Zerochain?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
A privacy-oriented blockchain on Substrate

## Status
For now, only supported for the confidential payment PoC.

- Balances of each accounts are encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678399-6d00ac80-4b48-11e9-9c8d-d1ec2b668761.png" width="800px">
</div>

- Transfer amounts are encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678984-9cfc7f80-4b49-11e9-9784-576dcaa35ca9.png" width="800px">
</div>

More features will be added... :muscle:

## Usage
### Initial Setup
```
curl https://sh.rustup.rs -sSf | sh

rustup update stable
rustup update nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
cargo +nightly install --git https://github.com/alexcrichton/wasm-gc
```
You will also need to install the following packages:
- Mac:
```
brew install cmake pkg-config openssl git llvm
```
- Linux:
```
sudo apt install cmake pkg-config libssl-dev git clang libclang-dev
```

### Building
```
git clone git@github.com:LayerXcom/zero-chain.git
cd zero-chain
./build.sh
cargo build --release
```

### Running the client
```
./target/release/zero-chain --dev
```
- If you want to clear your old chain's history:
```
./target/release/zero-chain purge-chain --dev
```

### Sending transactions
This tutorial will explain the basic confidential transfer on Zerochain. Alice has the **encrypted** balance of 100 coins and sends **encrypted** 10 coins to Bob. So, Alice's encrypted balance will be 90 coins and Bob will get the encrypted 10 coins. All operations are done encrypted by ElGamal encryption and zk-SNARKs.

1. Run the UI apps
The UI repository is here:
https://github.com/LayerXcom/zero-chain-ui

2. Generate the transaction components from CLI
- Get the proving key and the veifying key for zk-SNARKs
```
./target/release/zerochain-cli setup
```

- Generate the transaction components (Executing the zero knowledge proving and the encryption)
```
./target/release/zero-chain-cli generate-tx
```

3. Fill out the form
You can send the transaction from firefox browser.

<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54687970-228b2a00-4b60-11e9-8c26-fdfbbb3a17d8.png" width="1000px">
</div>


## Design philosophy
- Efficient confidentiality
- Various computation
- Modular cryptography

### Maintainers
- [Osuke](https://twitter.com/zoom_zoomzo)
