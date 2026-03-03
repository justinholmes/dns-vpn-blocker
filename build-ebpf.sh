#!/usr/bin/env bash
# Build the XDP eBPF program and copy the object next to the release binary.
# Run this before `cargo build --release`.
set -e

# Install prerequisites once
rustup install nightly 2>/dev/null || true
rustup component add rust-src --toolchain nightly 2>/dev/null || true
cargo install bpf-linker 2>/dev/null || true

# RUSTFLAGS env var overrides config-level rustflags (prevents -Wl,-rpath from leaking into bpf-linker)
RUSTFLAGS='--cfg bpf_target_arch="x86_64"' cargo +nightly build \
    -p vpn-blocker-ebpf \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

cp target/bpfel-unknown-none/release/vpn-blocker-ebpf \
   target/release/vpn-blocker-ebpf

echo "eBPF object ready at target/release/vpn-blocker-ebpf"
