# Zerochain
[![Build Status](https://travis-ci.com/LayerXcom/zero-chain.svg?branch=master)](https://travis-ci.com/LayerXcom/zero-chain)
[![Gitter](https://badges.gitter.im/LayerXcom/Zerochain.svg)](https://gitter.im/LayerXcom/Zerochain?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Zerochain is a generic parivacy-protecting layer on top of Substrate. It provides some useful substrate modules and toolkit for protecting user's privacy and sensitive data stored on chain.
It is designed to get efficient zero-knowledge proving, reduce the on-chain storage cost and bring the flexibility for developing applications.

Have a look at [Zerochain Book](https://layerxcom.github.io/zerochain-book/) for usage and more information about using Zerochain.

## Status
**WARNING: Zerochain is alpha quality software, improvements and fixes are made frequently.**

For now, only supported for the PoC of confidential payment inspired by [Zether](https://crypto.stanford.edu/~buenz/papers/zether.pdf) paper.

- Balance for each account is encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678399-6d00ac80-4b48-11e9-9c8d-d1ec2b668761.png" width="400px">
</div>

- Transfer amount is encrypted
<div align="center">
<img src="https://user-images.githubusercontent.com/20852667/54678984-9cfc7f80-4b49-11e9-9784-576dcaa35ca9.png" width="400px">
</div>

More features will be added... :muscle::muscle:

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

## Usage and Tutorial
Documented in [Zerochain Book](https://layerxcom.github.io/zerochain-book/).

### Related Repositories
- [polkadot.rs](https://github.com/LayerXcom/polkadot.rs)
- [ZFace](https://github.com/LayerXcom/zero-chain/tree/master/zface) (in same repo currently)
- [librustzcash for zerochain](https://github.com/LayerXcom/librustzcash)

### Documentations
- [Announcing Zerochain: Applying zk-SNARKs to Substrate](https://medium.com/layerx/announcing-zerochain-5b08e158355d)
- (Work in progress) [Zerochain Book](https://layerxcom.github.io/zerochain-book/)

### References
- [Substrate repo](https://github.com/paritytech/substrate)
- [Substrate Developer Hub](https://substrate.dev/)
- [Zcash Protocol Specification](https://github.com/zcash/zips/blob/master/protocol/protocol.pdf)
- [Zether](https://crypto.stanford.edu/~buenz/papers/zether.pdf): Towards Privacy in a Smart Contract World
- [Sonic](https://eprint.iacr.org/2019/099.pdf): Zero-Knowledge SNARKs from Linear-Size Universal and Updatable Structured Reference Strings

## Contributing
- Feel free to submit your own issues and PRs
- For further discussions and questions talk to us on [Gitter](https://gitter.im/LayerXcom/Zerochain)

### Maintainers
- [Osuke](https://twitter.com/zoom_zoomzo)
