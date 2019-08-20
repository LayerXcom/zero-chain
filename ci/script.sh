#!/usr/bin/env bash

set -eux

# Enable warnings about unused extern crates
export RUSTFLAGS=" -W unused-extern-crates"

# Install rustup and the specified rust toolchain.
# curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain=$RUST_TOOLCHAIN -y

# Load cargo environment. Specifically, put cargo into PATH.
# source ~/.cargo/env

case $TARGET in
	"native")
		rustc --version
		rustup --version
		cargo --version
		sudo apt-get -y update
		sudo apt-get install -y cmake pkg-config libssl-dev

		cargo build --release --all
		;;

	"wasm")
		rustup component add rustc --toolchain nightly-2019-07-16-x86_64-unknown-linux-gnu
		rustup target add wasm32-unknown-unknown --toolchain nightly
		rustc --version
		rustup --version
		cargo --version
		# Install prerequisites and build all wasm projects
		./init.sh
		./build.sh
		;;
esac