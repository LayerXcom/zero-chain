# Zerochain
[![Build Status](https://travis-ci.com/LayerXcom/zero-chain.svg?branch=master)](https://travis-ci.com/LayerXcom/zero-chain)
[![Gitter](https://badges.gitter.im/LayerXcom/Zerochain.svg)](https://gitter.im/LayerXcom/Zerochain?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Zerochain is a privacy-preserving blockchain on substrate.
It is designed to get efficient zero-knowledge proving, reduce the on-chain storage cost and bring the flexibility for developing applications.

## Status
**WARNING: Zerochain is alpha quality software, improvements and fixes are made frequently, and documentation for technical details doesn't yet exist.**

For now, only supported for the "confidential payment PoC" inspired by [Zether](https://crypto.stanford.edu/~buenz/papers/zether.pdf) paper.

- Balance for each account is encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678399-6d00ac80-4b48-11e9-9c8d-d1ec2b668761.png" width="400px">
</div>

- Transfer amount is encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678984-9cfc7f80-4b49-11e9-9784-576dcaa35ca9.png" width="400px">
</div>

More features will be added... :muscle::muscle:

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

## A brief tutorial for Sending transactions
This tutorial will explain the basic confidential transfer on Zerochain. Alice has the **encrypted** balance of 100 coins and sends **encrypted** 10 coins to Bob. So, Alice's balance will be 90 coins and Bob will get the 10 coins. All operations are done encrypted by ElGamal encryption and zk-SNARKs.

1. Setup for zkSNARKs from CLI
- Get the proving key and the veifying key for zk-SNARKs
```
./target/release/zero-chain-cli setup
```

2. Run the nodes
```
./target/release/zero-chain --dev
```
- If you want to clear your old chain's history:
```
./target/release/zero-chain purge-chain --dev
```

3. Run the UI apps

The UI repository is here:
https://github.com/LayerXcom/zero-chain-ui

4. Generate the transaction from CLI
- Generate the transaction components (Computing a zero-knowledge proofs and an encryption)
```
./target/release/zero-chain-cli generate-tx
```

- For more information (if you want to set the customized amount and address)
```
./target/release/zero-chain-cli generate-tx --help
```

5. Fill out the form:

You can send the transaction from firefox browser.

<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54687970-228b2a00-4b60-11e9-8c26-fdfbbb3a17d8.png" width="1100px">
</div>

### Documentations
- [Announcing Zerochain: Applying zk-SNARKs to Substrate](https://medium.com/layerx/announcing-zerochain-5b08e158355d)

### References
- [Substrate](https://github.com/paritytech/substrate)
- [Zcash Protocol Specification](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf)
- [Zether](https://crypto.stanford.edu/~buenz/papers/zether.pdf): Towards Privacy in a Smart Contract World
- [Sonic](https://eprint.iacr.org/2019/099.pdf): Zero-Knowledge SNARKs from Linear-Size Universal and Updatable Structured Reference Strings

## Contributing
- Feel free to submit your own issues and PRs
- For further discussions and questions talk to us on [Gitter](https://gitter.im/LayerXcom/Zerochain)

### Maintainers
- [Osuke](https://twitter.com/zoom_zoomzo)
