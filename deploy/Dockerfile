FROM rust:1.98-slim AS build
WORKDIR /app
COPY . .
RUN cargo build --workspace --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/target/release/rtunneld /usr/local/bin/
COPY --from=build /app/target/release/rtunnel-agent /usr/local/bin/
COPY --from=build /app/target/release/rtunnel /usr/local/bin/
CMD ["/usr/local/bin/rtunneld", "serve"]
