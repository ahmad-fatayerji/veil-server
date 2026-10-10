FROM rust:1.99-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home veil
COPY --from=build /build/target/release/veil-server /usr/local/bin/veil-server
USER 10001:10001
ENTRYPOINT ["veil-server"]
