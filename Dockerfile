# MASQUE server — multi-stage build
# Stage 1: build
FROM rust:1.88-bookworm AS builder

# cmake and go build BoringSSL; clang/libclang-dev are for the bindgen step in
# boring-sys, which fails with "Unable to find libclang" without them.
RUN apt-get update \
    && apt-get install -y cmake golang-go clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency caching layer: copy manifests + stub sources, build deps first.
#
# The bench target declared in Cargo.toml has to exist as a file or cargo
# refuses to parse the manifest at all, so it is stubbed here alongside the
# sources and replaced by the real one below.
COPY Cargo.toml Cargo.lock ./
COPY tools/masque-e2e/Cargo.toml tools/masque-e2e/Cargo.toml
COPY tools/masque-probe/Cargo.toml tools/masque-probe/Cargo.toml
RUN mkdir -p src benches tools/masque-e2e/src tools/masque-probe/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > benches/core.rs \
    && echo "fn main() {}" > tools/masque-e2e/src/main.rs \
    && echo "fn main() {}" > tools/masque-probe/src/main.rs \
    && cargo build --release -p masque-server 2>/dev/null || true \
    && rm -f target/release/masque-server target/release/deps/masque_server-* \
    && rm -rf src tools/masque-e2e/src tools/masque-probe/src

# Copy real source and build.
COPY src/ src/
COPY benches/ benches/
COPY tools/masque-e2e/ tools/masque-e2e/
COPY tools/masque-probe/ tools/masque-probe/
RUN touch src/main.rs src/lib.rs && cargo build --release -p masque-server --bin masque-server

# Stage 2: minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates iproute2 iptables && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/masque-server /usr/local/bin/masque-server

EXPOSE 4433/udp

ENTRYPOINT ["masque-server"]
