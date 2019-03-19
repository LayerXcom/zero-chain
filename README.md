# zero-chain
A privacy-oriented blockchain on Substrate

## Status
Work in progress... :muscle:

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

### Cli
Generate the zk-SNARKs proving key and veifying key
```
cd demo/cli
cargo run --release setup
```

Generate the Alice's transaction
```
cargo run --release generate-tx
```

### Interact with the blockchain
See here: 
https://github.com/LayerXcom/zero-chain-ui

## Design philosophy
- Efficient confidentiality
- Various computation
- Modular cryptography


### Maintainers
- [Osuke](https://twitter.com/zoom_zoomzo)
