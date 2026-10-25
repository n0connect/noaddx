# ==============================================================================
# noaddx. Makefile
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Detect Docker Compose v2 ("docker compose") vs v1 ("docker-compose")
DOCKER_COMPOSE ?= $(shell if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "docker-compose-not-found"; fi)

# Project paths
ENV_FILE := .env
ENV_EXAMPLE := .env.example

# Crypto engine compiled into the backend: openssl (default, libcrypto >= 3.2 via cgo) or
# native (Go standard library). Both are byte-for-byte equivalent (make test-equivalence).
ENGINE ?= openssl
ENGINES := openssl native
ifeq ($(filter $(ENGINE),$(ENGINES)),)
$(error ENGINE must be one of: $(ENGINES) (got "$(ENGINE)"))
endif
GO_TAGS_openssl := openssl
GO_TAGS_native :=
CGO_openssl := 1
CGO_native := 0

# Release tags: noaddx-<engine>-vX.Y.Z on main; noaddx-<engine>-dev follow noaddx-dev
DEV_BRANCH := noaddx-dev
RELEASE_BRANCH := main
COMPOSE_ENV := ENGINE=$(ENGINE)
# Includes the opt-in tor service, so stopping and listing always cover it too
COMPOSE_ALL := $(DOCKER_COMPOSE) -f docker-compose.yaml --profile onion
# Frontend manifest: what the release workflow signs and verify-frontend checks against
MANIFEST ?= frontend.sha256

.PHONY: all help setup check-deps check-docker build up onion onion-address start run down stop restart logs ps clean \
        test test-engines test-equivalence test-run test-unit test-crypto test-all test-db \
        build-ref tag-dev release check-clean-branch-dev check-clean-branch-release shell-backend shell-db \
        manifest verify-frontend

## -----------------------------------------------------------------------------
## Help
## -----------------------------------------------------------------------------

help:
	@echo "noaddx. build system"
	@echo "======================"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Crypto engine: ENGINE=openssl (default) | native  e.g. make up ENGINE=native"
	@echo ""
	@echo "Targets:"
	@echo "  setup         Generate .env configuration with fresh cryptographic keys"
	@echo "  build         Build Docker container images for ENGINE"
	@echo "  up            Build and start services in background for ENGINE"
	@echo "  onion         Like up, and publish the app as a Tor onion service"
	@echo "  onion-address Print the onion address (published by make onion)"
	@echo "  down          Stop and remove running containers"
	@echo "  restart       Restart services"
	@echo "  logs          Stream container logs (Ctrl+C to exit)"
	@echo "  ps            Display service container status"
	@echo "  clean         Stop services, delete images, volumes and test artifacts"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test          Full Go suite for ENGINE in Docker (openssl also runs equivalence)"
	@echo "  test-engines  Full Go suite for both engines, one after the other"
	@echo "  test-equivalence  Prove both engines give byte-identical results (Docker)"
	@echo "  test-run      Run Docker test suite; if passed, start services"
	@echo "  test-unit     Run Go unit tests locally for ENGINE (no database needed)"
	@echo "  test-crypto   Run frontend WebCrypto derivation tests (Node.js 20+)"
	@echo "  test-all      Run local Go unit tests and frontend crypto tests"
	@echo "  test-db       Run Go database and integration tests (requires local PostgreSQL)"
	@echo ""
	@echo "Release Targets:"
	@echo "  build-ref     Build the backend image of any tag or commit: make build-ref REF=noaddx-openssl-v1.0.0"
	@echo "  tag-dev       Test both engines, then move noaddx-{openssl,native}-dev to $(DEV_BRANCH) HEAD"
	@echo "  release       Test both engines on $(RELEASE_BRANCH), tag noaddx-{openssl,native}-VERSION: make release VERSION=v1.0.0"
	@echo "  manifest      Write $(MANIFEST): SHA-256 of every file the frontend serves (signed in each release)"
	@echo "  verify-frontend  Check an instance serves exactly $(MANIFEST): make verify-frontend URL=https://host"
	@echo ""
	@echo "Utility Targets:"
	@echo "  shell-backend Open interactive shell inside backend container"
	@echo "  shell-db      Open PostgreSQL CLI inside database container"

## -----------------------------------------------------------------------------
## Environment Configuration & Key Generation
## -----------------------------------------------------------------------------

setup:
	@if [ "$(DOCKER_COMPOSE)" = "docker-compose-not-found" ]; then \
		echo "ERROR: Docker Compose is required but neither 'docker compose' nor 'docker-compose' was found in PATH."; \
		exit 1; \
	fi
	@if ! command -v openssl >/dev/null 2>&1; then \
		echo "ERROR: openssl is required (only 'openssl rand' is used; OpenSSL or LibreSSL both work)."; \
		exit 1; \
	fi
	@if [ -f "$(ENV_FILE)" ]; then \
		echo "[INFO] $(ENV_FILE) already exists. Skipping key generation."; \
		echo "       To regenerate keys, remove $(ENV_FILE) first: rm $(ENV_FILE)"; \
	else \
		echo "[INFO] Generating fresh cryptographic keys and $(ENV_FILE)..."; \
		umask 077; \
		JWT_SECRET=$$(openssl rand -hex 32); \
		PEPPER=$$(openssl rand -hex 32); \
		MASTER_KEY=$$(openssl rand -hex 32); \
		MASTER_KEY_ID=$$(openssl rand -hex 4); \
		DB_PASSWORD=$$(openssl rand -hex 24); \
		sed -e "s|^JWT_SECRET=.*|JWT_SECRET=$$JWT_SECRET|" \
		    -e "s|^ACCOUNT_LOOKUP_PEPPER=.*|ACCOUNT_LOOKUP_PEPPER=$$PEPPER|" \
		    -e "s|^MASTER_KEY_ACTIVE=.*|MASTER_KEY_ACTIVE=$$MASTER_KEY|" \
		    -e "s|^MASTER_KEY_ACTIVE_ID=.*|MASTER_KEY_ACTIVE_ID=$$MASTER_KEY_ID|" \
		    -e "s|^DB_PASSWORD=.*|DB_PASSWORD=$$DB_PASSWORD|" \
		    $(ENV_EXAMPLE) > $(ENV_FILE); \
		chmod 600 $(ENV_FILE); \
		echo "[OK] $(ENV_FILE) created successfully with secure permissions (0600)."; \
	fi

$(ENV_FILE):
	@$(MAKE) setup

## -----------------------------------------------------------------------------
## Container Management
## -----------------------------------------------------------------------------

check-docker:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "[ERROR] Docker is not installed or not in PATH."; exit 1; \
	fi; \
	if ! docker info >/dev/null 2>&1; then \
		echo "[ERROR] Docker daemon is not running. Please start Docker Desktop (or OrbStack/Colima) and try again."; exit 1; \
	fi

build: check-docker $(ENV_FILE)
	@echo "[INFO] Building Docker images (crypto engine: $(ENGINE))..."
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.yaml build

up: check-docker $(ENV_FILE)
	@echo "[INFO] Starting services (crypto engine: $(ENGINE))..."
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.yaml up -d --build
	@echo "[OK] Services running"
	@$(DOCKER_COMPOSE) -f docker-compose.yaml ps

# The tor service is opt-in: it makes this instance reachable from anywhere through Tor
onion: check-docker $(ENV_FILE)
	@echo "[INFO] Starting services and the onion service (crypto engine: $(ENGINE))..."
	@$(COMPOSE_ENV) $(COMPOSE_ALL) up -d --build
	@echo "[OK] Services running; the onion address appears once tor has published it (about a minute):"
	@echo "     make onion-address"

onion-address:
	@docker exec noaddx-tor cat /var/lib/tor/noaddx/hostname 2>/dev/null \
		|| echo "[INFO] Not published yet: run make onion, then retry in a minute"

start: up
run: up

down:
	@echo "[INFO] Stopping services..."
	@$(COMPOSE_ALL) down

stop: down

restart:
	@echo "[INFO] Restarting services..."
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.yaml restart

logs:
	@$(COMPOSE_ALL) logs -f

ps:
	@$(COMPOSE_ALL) ps

clean:
	@echo "[INFO] Cleaning containers, volumes and test artifacts..."
	@$(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v --rmi local 2>/dev/null || true
	@$(COMPOSE_ALL) down -v --rmi local 2>/dev/null || true
	@docker images --filter "reference=*noaddx*" -q | xargs docker rmi -f 2>/dev/null || true
	@rm -rf test-results
	@echo "[OK] Clean complete"

## -----------------------------------------------------------------------------
## Testing
## -----------------------------------------------------------------------------

test: check-docker
	@echo "[INFO] Running the containerized test suite (crypto engine: $(ENGINE))..."
	@mkdir -p test-results
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml build
	@$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml up --abort-on-container-exit --exit-code-from test-runner; \
	EXIT_CODE=$$?; \
	$(COMPOSE_ENV) $(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v; \
	if [ $$EXIT_CODE -eq 0 ]; then \
		echo "[OK] All containerized tests passed ($(ENGINE))"; \
	else \
		echo "[ERROR] Tests failed with exit code $$EXIT_CODE ($(ENGINE))"; \
	fi; \
	exit $$EXIT_CODE

test-engines:
	@for engine in $(ENGINES); do $(MAKE) --no-print-directory test ENGINE=$$engine || exit 1; done
	@echo "[OK] Both crypto engines pass the complete suite"

# Links both engines into one test binary and compares every primitive (no database needed)
test-equivalence: check-docker
	@echo "[INFO] Proving openssl and native engines are byte-for-byte equivalent..."
	@ENGINE=openssl $(DOCKER_COMPOSE) -f docker-compose.test.yaml build test-runner
	@ENGINE=openssl $(DOCKER_COMPOSE) -f docker-compose.test.yaml run --rm --no-deps -e CGO_ENABLED=1 test-runner \
		go test -count=1 -tags 'test openssl' -v ./internal/cryptoengine/...

test-run: test up

test-unit:
	@echo "[INFO] Running local Go unit tests (crypto engine: $(ENGINE), no database)..."
	@cd backend && CGO_ENABLED=$(CGO_$(ENGINE)) go test -tags "test $(GO_TAGS_$(ENGINE))" ./internal/... ./tests/auth/... ./tests/encryption/... ./tests/identity/... ./tests/middleware/... ./tests/utils/...

test-crypto:
	@echo "[INFO] Running frontend WebCrypto verification tests..."
	@node --test frontend/tests/*.test.mjs

test-all: test-crypto test-unit

# Database and integration tests against a local PostgreSQL (override: make test-db TEST_DB_PORT=5433)
TEST_DB_HOST ?= 127.0.0.1
TEST_DB_PORT ?= 5432
TEST_DB_USER ?= postgres
TEST_DB_PASSWORD ?= postgres
TEST_DB_NAME ?= noaddx_test

test-db:
	@echo "[INFO] Running database and integration tests (requires local PostgreSQL)..."
	@cd backend && DB_HOST=$(TEST_DB_HOST) DB_PORT=$(TEST_DB_PORT) DB_USER=$(TEST_DB_USER) \
		DB_PASSWORD=$(TEST_DB_PASSWORD) DB_NAME=$(TEST_DB_NAME) CGO_ENABLED=$(CGO_$(ENGINE)) \
		go test -p 1 -count=1 -tags "test $(GO_TAGS_$(ENGINE))" ./tests/database/... ./tests/integration/...

## -----------------------------------------------------------------------------
## Releases
## -----------------------------------------------------------------------------

# Builds the backend image of any tag or commit from git history (not the working tree).
# The engine follows the tag name (noaddx-openssl-* / noaddx-native-*) unless ENGINE is given.
build-ref: check-docker
	@if [ -z "$(REF)" ]; then echo "[ERROR] usage: make build-ref REF=<tag|commit> [ENGINE=openssl|native]"; exit 1; fi
	@git rev-parse --verify --quiet "$(REF)^{commit}" >/dev/null || { echo "[ERROR] unknown ref: $(REF)"; exit 1; }
	@engine="$(ENGINE)"; \
	case "$(REF)" in noaddx-openssl-*) engine=openssl ;; noaddx-native-*) engine=native ;; esac; \
	if [ "$(origin ENGINE)" = "command line" ] && [ "$$engine" != "$(ENGINE)" ]; then \
		echo "[ERROR] REF $(REF) is a $$engine release; drop ENGINE or pick a matching tag"; exit 1; fi; \
	echo "[INFO] Building $(REF) ($$(git rev-parse --short "$(REF)^{commit}")) with the $$engine engine..."; \
	git archive --format=tar "$(REF)" | docker build --build-arg ENGINE=$$engine -f dev.backend.Dockerfile \
		-t "noaddx-backend:$$(echo '$(REF)' | tr '/:' '--')" - && \
	echo "[OK] Image: noaddx-backend:$$(echo '$(REF)' | tr '/:' '--')"

# Moves the dev tags to the tested HEAD of the dev branch (both engines must pass first)
tag-dev: check-clean-branch-dev test-engines
	@for engine in $(ENGINES); do git tag -f -a "noaddx-$$engine-dev" -m "noaddx. $$engine engine, development build ($$(git rev-parse --short HEAD))" HEAD >/dev/null; done
	@git push -f origin $(foreach e,$(ENGINES),refs/tags/noaddx-$(e)-dev)
	@echo "[OK] noaddx-openssl-dev and noaddx-native-dev -> $$(git rev-parse --short HEAD)"

# Tags one tested commit of the release branch for both engines: make release VERSION=v1.0.0
release: check-clean-branch-release test-engines
	@if ! echo "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then echo "[ERROR] VERSION must look like v1.2.3"; exit 1; fi
	@for engine in $(ENGINES); do \
		if git rev-parse -q --verify "refs/tags/noaddx-$$engine-$(VERSION)" >/dev/null; then echo "[ERROR] noaddx-$$engine-$(VERSION) exists"; exit 1; fi; \
	done
	@for engine in $(ENGINES); do git tag -a "noaddx-$$engine-$(VERSION)" -m "noaddx. $(VERSION) ($$engine crypto engine)" HEAD; done
	@git push origin $(foreach e,$(ENGINES),refs/tags/noaddx-$(e)-$(VERSION))
	@echo "[OK] Released $(VERSION): $(foreach e,$(ENGINES),noaddx-$(e)-$(VERSION))"

check-clean-branch-dev:
	@[ "$$(git rev-parse --abbrev-ref HEAD)" = "$(DEV_BRANCH)" ] || { echo "[ERROR] check out $(DEV_BRANCH) first"; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "[ERROR] commit or stash your changes first"; exit 1; }

check-clean-branch-release:
	@[ "$$(git rev-parse --abbrev-ref HEAD)" = "$(RELEASE_BRANCH)" ] || { echo "[ERROR] releases are cut from $(RELEASE_BRANCH)"; exit 1; }
	@[ -z "$$(git status --porcelain)" ] || { echo "[ERROR] commit or stash your changes first"; exit 1; }

## -----------------------------------------------------------------------------
## Debug & Utilities
## -----------------------------------------------------------------------------

# Tracked files only (no local leftovers), paths as served under the web root
manifest:
	@git ls-files -- frontend ':!frontend/tests' | LC_ALL=C sort | sed 's|^frontend/||' \
		| (cd frontend && xargs shasum -a 256) > $(MANIFEST)
	@echo "[OK] $(MANIFEST): $$(wc -l < $(MANIFEST) | tr -d ' ') files"

# Fetches every file in MANIFEST from URL and compares hashes; index.html is served at /.
# For an onion address: CURL_OPTS="--socks5-hostname 127.0.0.1:9150" (Tor Browser's proxy)
verify-frontend:
	@test -n "$(URL)" || { echo "[ERROR] usage: make verify-frontend URL=https://host [MANIFEST=$(MANIFEST)]"; exit 1; }
	@test -s "$(MANIFEST)" || { echo "[ERROR] $(MANIFEST) missing: download it from the release or run make manifest"; exit 1; }
	@fail=0; while read -r want path; do \
		route="/$$path"; [ "$$path" = "index.html" ] && route="/"; \
		got=$$(curl -fsS $(CURL_OPTS) "$(URL)$$route" | shasum -a 256 | cut -d' ' -f1); \
		[ "$$got" = "$$want" ] || { echo "[MISMATCH] $$route"; fail=1; }; \
	done < $(MANIFEST); \
	if [ $$fail -eq 0 ]; then echo "[OK] $(URL) serves exactly $(MANIFEST)"; else exit 1; fi

shell-backend:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec backend /bin/sh

shell-db:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec postgres psql -U postgres -d noaddx
