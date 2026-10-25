FROM rust:1.98-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY crates ./crates

RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates openssh-server && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/rtunneld /usr/local/bin/
COPY --from=builder /build/target/release/rtunnel-agent /usr/local/bin/
COPY --from=builder /build/target/release/rtunnel /usr/local/bin/

RUN mkdir -p /var/lib/rtunnel /var/lib/rtunnel-agent /var/run/sshd

EXPOSE 4433/udp
CMD ["/usr/local/bin/rtunneld", "serve"]
