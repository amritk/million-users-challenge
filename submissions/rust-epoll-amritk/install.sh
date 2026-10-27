#!/usr/bin/env bash
# Ubuntu 24.04 x86_64, run once as root. Installs what BUILDING needs: a C toolchain (the linker, and cc for
# libdeflate, which the libdeflater crate compiles from source) and Rust 1.97.0 via rustup in /opt/rust.
# Running needs nothing extra: the binary links only glibc.
set -euo pipefail
RUST=1.97.0
if ! command -v cc >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq build-essential curl ca-certificates
fi
export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo
if [[ ! -x $CARGO_HOME/bin/rustup ]]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain "$RUST"
fi
$CARGO_HOME/bin/rustup toolchain install "$RUST" --profile minimal --no-self-update
chmod -R a+rX /opt/rust
$CARGO_HOME/bin/cargo "+$RUST" --version
