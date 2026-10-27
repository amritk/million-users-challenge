#!/usr/bin/env bash
# Release build as a normal user (dependencies pinned in Cargo.lock). Output: target/release/feed-server
set -euo pipefail
cd "$(dirname "$0")"
if [[ -x /opt/rust/cargo/bin/cargo ]]; then
  export RUSTUP_HOME=/opt/rust/rustup PATH="/opt/rust/cargo/bin:$PATH"
fi
export RUSTUP_TOOLCHAIN=1.97.0
# The benchmark boxes are identical machines, so build for the CPU it runs on.
export RUSTFLAGS="-C target-cpu=native ${RUSTFLAGS:-}"
cargo build --release --locked
