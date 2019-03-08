#!/usr/bin/env bash

set -e

PROJECT_ROOT=`git rev-parse --show-toplevel`

export CARGO_INCREMENTAL=0

# Save current directory.
pushd . >/dev/null

cd $ROOT

for SRC in runtime/wasm
do
  echo "*** Building webassembly binary in $SRC"
  cd "$PROJECT_ROOT/$SRC"

  ./build.sh

  cd - >> /dev/null
done

# Restore initial directory.
popd >/dev/null
