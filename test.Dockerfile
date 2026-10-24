# test.Dockerfile - the complete Go test suite against the disposable PostgreSQL of
# docker-compose.test.yaml (pure Go crypto, CGO disabled - RULES.md §1.1)
FROM golang:1.27.3-bookworm

WORKDIR /app

COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify

COPY backend/ .

RUN mkdir -p /test-results

# -p 1: the database packages share one database and must not run concurrently
CMD ["bash", "-c", "CGO_ENABLED=0 go test -p 1 -count=1 -tags=test ./... 2>&1 | tee /test-results/output.log; exit ${PIPESTATUS[0]}"]
