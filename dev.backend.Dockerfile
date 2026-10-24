# Backend image for either crypto engine (byte-for-byte equivalent, see docs/security/cryptography.md):
#   ENGINE=openssl  libcrypto 3.5 LTS from Debian trixie through cgo (default)
#   ENGINE=native   Go standard library crypto, static binary, CGO disabled
# Go 1.27.3+ carries the crypto/x509 fix (GO-2026-6809).
ARG ENGINE=openssl

FROM golang:1.27.3-trixie AS builder
ARG ENGINE

# OpenSSL headers come from Debian's signed packages (no source download to verify by hand)
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first for layer caching; go.sum pins and verifies every module
COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify

COPY backend/ .

# Reproducible, stripped binary (RULES.md §14.1); the engine is fixed at compile time
RUN case "$ENGINE" in \
      openssl) CGO_ENABLED=1 go build -tags openssl -trimpath -buildvcs=false -ldflags="-s -w" -o /out/noaddx ./cmd/server ;; \
      native)  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/noaddx ./cmd/server ;; \
      *) echo "ENGINE must be openssl or native (got '$ENGINE')" >&2; exit 1 ;; \
    esac

FROM debian:trixie-slim
ARG ENGINE

# libssl3t64 only for the OpenSSL engine; wget serves the compose healthcheck
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates wget $([ "$ENGINE" = openssl ] && echo libssl3t64) \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin noaddx

COPY --from=builder /out/noaddx /usr/local/bin/noaddx

LABEL org.opencontainers.image.title="noaddx backend" \
      noaddx.crypto-engine="${ENGINE}"

USER 10001:10001
EXPOSE 8080

CMD ["/usr/local/bin/noaddx"]
