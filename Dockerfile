FROM rust:1.80-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src/ src/
RUN cargo build --release --features "all-parsers,cli"

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/muninn /usr/local/bin/muninn
WORKDIR /case
ENTRYPOINT ["muninn"]
