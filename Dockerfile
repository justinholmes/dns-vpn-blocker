# ─── Stage 1: Build eBPF program ────────────────────────────────────────────
FROM ubuntu:24.04 AS ebpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gcc libssl-dev pkg-config \
    clang llvm lld libelf-dev linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (nightly required for eBPF build-std)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain nightly --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rust-src --toolchain nightly \
    && cargo install bpf-linker

WORKDIR /build
COPY vpn-blocker-ebpf/ vpn-blocker-ebpf/
COPY Cargo.toml Cargo.lock ./

# Build just the eBPF object (bpfel-unknown-none target)
RUN RUSTFLAGS='--cfg bpf_target_arch="x86_64"' \
    cargo +nightly build \
      -p vpn-blocker-ebpf \
      --target bpfel-unknown-none \
      -Z build-std=core \
      --release

# ─── Stage 2: Build userspace binary ─────────────────────────────────────────
FROM ubuntu:24.04 AS app-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gcc g++ libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY --from=ebpf-builder \
    /build/target/bpfel-unknown-none/release/vpn-blocker-ebpf \
    /build/target/bpfel-unknown-none/release/vpn-blocker-ebpf

COPY . .

# Build the userspace binary (links in the eBPF object via include_bytes!)
RUN cargo build --release

# ─── Stage 3: Runtime image ───────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsmasq iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=app-builder /build/target/release/vpn-blocker /usr/local/bin/vpn-blocker
COPY model.onnx /app/model.onnx

# dnsmasq config directory (vpn-blocker writes /etc/dnsmasq.d/vpn-blocker-domains.conf)
RUN mkdir -p /etc/dnsmasq.d

# Web UI port
EXPOSE 8080/tcp

# XDP requires the interface name; pass as CMD argument (e.g. eth0)
# Requires: --privileged --network=host (see docker-compose.yml)
ENTRYPOINT ["/usr/local/bin/vpn-blocker"]
CMD ["eth0"]

# ─── Stage 4: BIRD2 HA sidecar ────────────────────────────────────────────────
FROM ubuntu:24.04 AS bird2

RUN apt-get update && apt-get install -y --no-install-recommends \
    bird2 curl iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/bird /run/bird

COPY ha/bird.conf /etc/bird/bird.conf
COPY ha/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
