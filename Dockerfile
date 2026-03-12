# Stage 1: Build
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY templates/ templates/

RUN cargo build --release --locked

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tini

RUN addgroup -S duumbi && adduser -S duumbi -G duumbi

COPY --from=builder /build/target/release/duumbi-registry /usr/local/bin/duumbi-registry

RUN mkdir -p /data/modules && chown -R duumbi:duumbi /data

USER duumbi
WORKDIR /data

ENV DUUMBI_PORT=8080
ENV DUUMBI_DB=/data/registry.db
ENV DUUMBI_STORAGE=/data/modules

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["duumbi-registry", "--port", "8080", "--db", "/data/registry.db", "--storage-dir", "/data/modules"]
