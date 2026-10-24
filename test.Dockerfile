# test.Dockerfile - the complete Go test suite for one crypto engine against the disposable
# PostgreSQL of docker-compose.test.yaml. ENGINE=openssl also runs the equivalence suite,
# which links both engines and proves byte-identical results.
ARG ENGINE=openssl

FROM golang:1.27.3-trixie
ARG ENGINE
ENV ENGINE=${ENGINE}

RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/go.mod backend/go.sum ./
RUN go mod download && go mod verify

COPY backend/ .

RUN mkdir -p /test-results

# -p 1: the database packages share one database and must not run concurrently
CMD ["bash", "-c", "case \"$ENGINE\" in openssl) export CGO_ENABLED=1 TAGS='test openssl' ;; native) export CGO_ENABLED=0 TAGS=test ;; *) echo \"ENGINE must be openssl or native\" >&2; exit 1 ;; esac; echo \"crypto engine: $ENGINE\"; go test -p 1 -count=1 -tags \"$TAGS\" ./... 2>&1 | tee /test-results/output-$ENGINE.log; exit ${PIPESTATUS[0]}"]
