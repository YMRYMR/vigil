#!/bin/bash
set -euxo pipefail

cd "$SRC/vigil"
cargo fuzz build -O parse_client_hello
cp "fuzz/target/x86_64-unknown-linux-gnu/release/parse_client_hello" "$OUT/"
