# Zerochain
[![Build Status](https://travis-ci.com/LayerXcom/zero-chain.svg?branch=master)](https://travis-ci.com/LayerXcom/zero-chain)
[![Gitter](https://badges.gitter.im/LayerXcom/Zerochain.svg)](https://gitter.im/LayerXcom/Zerochain?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Zerochain is a generic parivacy-protecting layer on top of Substrate. It provides some useful substrate modules and toolkit for protecting user's privacy and sensitive data stored on chain.
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
This tutorial will explain the basic confidential transfer on Zerochain. Alice has the **encrypted** balance of 100 coins and sends **encrypted** 10 coins to Bob. The encrypted fee will be  subtracted from her balance. (By default, a base fee parameter is set to 1.) So, Alice's balance will be 89 coins and Bob will get the 10 coins. All operations are done encrypted by ElGamal encryption and zk-SNARKs.

Currently, there are two ways to interact with Zerochain.

- CLI (recommended)
- Browser

Browser UI is not maintenanced well, so might not be working. It is recommended to use with CLI.

### zeroc: Zerochain CLI

zeroc is a command-line utility which can interact with Zerochain.

#### Initial setup

- Install zeroc
```
cargo install --force --path zeroc
```

- Setup for zk-SNARKs

Generating a proving key and verifying key of zk-SNARKs, which are used for confidential payments.

```
zeroc snark setup
```

#### Interacting with Zerochain

- Generate key pairs

Generate random key pairs(mnemonic, seed, decryption key, and encryption key(public key)).
Alice's and Bob's key pairs are fixed and Alice already has some coins.

```
zeroc wallet init
```
This commands will print out like

```
Phrase `engage garden health add describe opinion penalty jelly wire tower moral inside` is account:
Seed: 0x3bb3f2f1667b7fccbf41818cc15c568a69eea54d86c8a035a82529bf1935dcc5
Decryption key: 0x9635af3157964b7f6c94a58166dece3872f67835a4453b47c7ec7c1c7afc5104
Encryption key (hex): 0xe035954716e1b3f4ff4c46d3f8ab4ad9453194381b9de7bae3789d97cd144b3c
Address (SS58): 5H8gW16RYqv9pqCVPv8GrxMm3byTiCfe16aA16uXwENsbytA
```

- Send transaction for confidential payment
```
zeroc tx send -a <AMOUNT> -s <Sender's SEED> -t <Recipient's PUBLIC KEY>
```

In the case, Alice sends 10 coins to Bob...
- Alice's seed: `0x416c696365202020202020202020202020202020202020202020202020202020`
- Bob's public key: `0x45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389`

```
zeroc send -a 10 -s 416c696365202020202020202020202020202020202020202020202020202020 -to 45e66da531088b55dcb3b273ca825454d79d2d1d5c4fa2ba4a12c1fa1ccd6389
```

This alice's seed is fixed and she already has 10,000 coins as initial supply.
For a convenient quick tutorial, all default parameters are set by default so you can just type the following command instead of above one.

```
zerc tx send
```

Alice, then, will have 9989 coins and Bob will have 10 coins.


- Get balance

Get a decrypyed balance using the user's decryption key.

```
zeroc tx balance -d <DECRYPTION KEY>
```

To get alice's balance...

```
zeroc tx balance -d b0451b0bfab2830a75216779e010e0bfd2e6d0b4e4b1270dfcdfd0d538509e02
```

As tutorial, you can just type the following commands to get Alice's balance.

```
zeroc tx balance
```

It will print out `9989` coins in this tutorial.

### Browser (MAY be obsoleted)

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
- (Work in progress) [Zerochain Book](https://layerxcom.github.io/zerochain-book/)

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
