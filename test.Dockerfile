# test.Dockerfile - Test image with pure Go crypto (no OpenSSL)

FROM golang:1.21-bookworm

WORKDIR /app

# Build dependencies (minimal - no OpenSSL needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY backend/go.mod backend/go.sum* ./
RUN go mod download

COPY backend/ .

RUN mkdir -p /test-results

# Run unit tests with CGO disabled (pure Go crypto - RULES.md §1.1)
CMD ["bash", "-c", "CGO_ENABLED=0 go test -tags=test -v ./internal/pow/... ./tests/handlers/... ./tests/utils/... ./tests/middleware/... ./tests/encryption/... ./tests/auth/... 2>&1 | tee /test-results/output.log; exit ${PIPESTATUS[0]}"]
