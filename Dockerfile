# MASQUE server — multi-stage build
# Stage 1: build
FROM rust:1.88-bookworm AS builder

RUN apt-get update && apt-get install -y cmake golang-go && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency caching layer: copy manifests + stub sources, build deps first.
COPY Cargo.toml Cargo.lock ./
COPY tools/masque-e2e/Cargo.toml tools/masque-e2e/Cargo.toml
RUN mkdir -p src tools/masque-e2e/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > tools/masque-e2e/src/main.rs \
    && cargo build --release -p masque-server 2>/dev/null || true \
    && rm -f target/release/masque-server target/release/deps/masque_server-* \
    && rm -rf src tools/masque-e2e/src

# Copy real source and build.
COPY src/ src/
COPY tools/masque-e2e/ tools/masque-e2e/
RUN touch src/main.rs src/lib.rs && cargo build --release -p masque-server --bin masque-server

# Stage 2: minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates iproute2 iptables && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/masque-server /usr/local/bin/masque-server

EXPOSE 4433/udp

ENTRYPOINT ["masque-server"]
