#!/usr/bin/env bash

set -e

echo "*** Initialising WASM build environment"

if [ -z $CI_PROJECT_NAME ] ; then
#    rustup update nightly
   rustup override set nightly-2019-07-16
   rustup update stable
fi

rustup target add wasm32-unknown-unknown --toolchain nightly
rustup component add rustc --toolchain nightly-2019-07-16-x86_64-unknown-linux-gnu

# Install wasm-gc. It's useful for stripping slimming down wasm binaries.
command -v wasm-gc || \
	cargo +nightly install --git https://github.com/alexcrichton/wasm-gc --force