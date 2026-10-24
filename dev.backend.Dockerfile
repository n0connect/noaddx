FROM golang:1.21-bookworm AS builder

WORKDIR /app

# Copy go mod files first for better layer caching
COPY backend/go.mod ./
# Copy go.sum if it exists (optional for first build)
COPY backend/go.sum* ./

# Download dependencies (cache layer if go.mod/go.sum unchanged)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN go mod download

# Copy source code
COPY backend/ .

# Build the application with CGO disabled (pure Go crypto - RULES.md §1.1)
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/server

# Final stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/main .

EXPOSE 8080

CMD ["./main"]
