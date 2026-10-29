FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p yany-relay

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/yany-relay /usr/local/bin/yany-relay
COPY --from=build /src/target/release/yany-token /usr/local/bin/yany-token
EXPOSE 6568
VOLUME ["/data/tls"]
ENV YANY_RELAY_BIND=0.0.0.0:6568
ENV YANY_JOIN_TOKEN_FILE=/data/tls/join.token
ENV RUST_LOG=info
CMD ["yany-relay", "--bind", "0.0.0.0:6568", "--dev-cert-dir", "/data/tls"]
