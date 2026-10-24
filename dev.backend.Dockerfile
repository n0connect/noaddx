# Build: pure Go (CGO disabled, crypto from the standard library - RULES.md §1.1).
# 1.27.3+ carries the crypto/x509 fix (GO-2026-6809).
FROM golang:1.27.3-bookworm AS builder

WORKDIR /src

# Dependencies first for layer caching; go.sum pins and verifies every module
COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify

COPY backend/ .

# Reproducible, stripped, static binary (RULES.md §14.1)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/noaddx ./cmd/server

FROM debian:bookworm-slim

# wget only serves the compose healthcheck; the service runs as an unprivileged user
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates wget \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin noaddx

COPY --from=builder /out/noaddx /usr/local/bin/noaddx

USER 10001:10001
EXPOSE 8080

CMD ["/usr/local/bin/noaddx"]
