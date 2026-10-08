# syntax=docker/dockerfile:1.7

# Both base images are pinned to the official multi-architecture manifest digest.
FROM rust:1.88.0-alpine3.22@sha256:9dfaae478ecd298b6b5a039e1f2cc4fc040fc818a2de9aa78fa714dea036574d AS builder
WORKDIR /src

COPY Cargo.toml Cargo.lock ./
COPY crates/protocol/Cargo.toml crates/protocol/Cargo.toml
COPY crates/transfer/Cargo.toml crates/transfer/Cargo.toml
COPY apps/server/Cargo.toml apps/server/Cargo.toml
COPY apps/desktop/Cargo.toml apps/desktop/Cargo.toml
COPY crates/protocol/src crates/protocol/src
COPY crates/transfer/src crates/transfer/src
COPY apps/server/src apps/server/src
COPY apps/desktop/src apps/desktop/src

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build -p cyclar-server --release --locked && \
    mkdir -p /out && \
    cp target/release/cyclar-server /out/cyclar-server

FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN addgroup -S -g 1000 cyclar && \
    adduser -S -D -H -u 1000 -G cyclar cyclar && \
    mkdir -p /var/lib/cyclar && \
    chown 1000:1000 /var/lib/cyclar

COPY --from=builder /out/cyclar-server /usr/local/bin/cyclar-server
COPY LICENSE /usr/share/licenses/cyclar/LICENSE

USER 1000:1000
WORKDIR /var/lib/cyclar
EXPOSE 8080
STOPSIGNAL SIGINT
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/cyclar-server"]
CMD ["serve", "--data-dir", "/var/lib/cyclar", "--listen", "0.0.0.0:8080", "--behind-tls-proxy"]
