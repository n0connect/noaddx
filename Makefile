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

.PHONY: all help setup check-deps check-docker build up start run down stop restart logs ps clean \
        test test-run test-unit test-crypto test-all test-db shell-backend shell-db

## -----------------------------------------------------------------------------
## Help
## -----------------------------------------------------------------------------

help:
	@echo "noaddx. build system"
	@echo "======================"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  setup         Generate .env configuration with fresh cryptographic keys"
	@echo "  build         Build Docker container images"
	@echo "  up            Build and start services in background (default if .env exists)"
	@echo "  down          Stop and remove running containers"
	@echo "  restart       Restart services"
	@echo "  logs          Stream container logs (Ctrl+C to exit)"
	@echo "  ps            Display service container status"
	@echo "  clean         Stop services, delete images, volumes and test artifacts"
	@echo ""
	@echo "Testing Targets:"
	@echo "  test          Run full test suite in isolated Docker container"
	@echo "  test-run      Run Docker test suite; if passed, start services"
	@echo "  test-unit     Run Go unit tests locally (no database needed)"
	@echo "  test-crypto   Run frontend WebCrypto derivation tests (Node.js 20+)"
	@echo "  test-all      Run local Go unit tests and frontend crypto tests"
	@echo "  test-db       Run Go database and integration tests (requires local PostgreSQL)"
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
	@echo "[INFO] Building Docker images..."
	@$(DOCKER_COMPOSE) -f docker-compose.yaml build

up: check-docker $(ENV_FILE)
	@echo "[INFO] Starting services..."
	@$(DOCKER_COMPOSE) -f docker-compose.yaml up -d
	@echo "[OK] Services running"
	@$(DOCKER_COMPOSE) -f docker-compose.yaml ps

start: up
run: up

down:
	@echo "[INFO] Stopping services..."
	@$(DOCKER_COMPOSE) -f docker-compose.yaml down

stop: down

restart:
	@echo "[INFO] Restarting services..."
	@$(DOCKER_COMPOSE) -f docker-compose.yaml restart

logs:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml logs -f

ps:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml ps

clean:
	@echo "[INFO] Cleaning containers, volumes and test artifacts..."
	@$(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v --rmi local 2>/dev/null || true
	@$(DOCKER_COMPOSE) -f docker-compose.yaml down -v --rmi local 2>/dev/null || true
	@docker images --filter "reference=*noaddx*" -q | xargs docker rmi -f 2>/dev/null || true
	@rm -rf test-results
	@echo "[OK] Clean complete"

## -----------------------------------------------------------------------------
## Testing
## -----------------------------------------------------------------------------

test:
	@echo "[INFO] Running containerized test suite..."
	@mkdir -p test-results
	@$(DOCKER_COMPOSE) -f docker-compose.test.yaml build
	@$(DOCKER_COMPOSE) -f docker-compose.test.yaml up --abort-on-container-exit --exit-code-from test-runner; \
	EXIT_CODE=$$?; \
	$(DOCKER_COMPOSE) -f docker-compose.test.yaml down -v; \
	if [ $$EXIT_CODE -eq 0 ]; then \
		echo "[OK] All containerized tests passed"; \
	else \
		echo "[ERROR] Tests failed with exit code $$EXIT_CODE"; \
	fi; \
	exit $$EXIT_CODE

test-run: test up

test-unit:
	@echo "[INFO] Running local Go unit tests (no database)..."
	@cd backend && go test -tags=test ./internal/... ./tests/auth/... ./tests/encryption/... ./tests/identity/... ./tests/middleware/... ./tests/utils/...

test-crypto:
	@echo "[INFO] Running frontend WebCrypto verification tests..."
	@node --test frontend/tests/

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
		DB_PASSWORD=$(TEST_DB_PASSWORD) DB_NAME=$(TEST_DB_NAME) \
		go test -p 1 -count=1 -tags=test ./tests/database/... ./tests/integration/...

## -----------------------------------------------------------------------------
## Debug & Utilities
## -----------------------------------------------------------------------------

shell-backend:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec backend /bin/sh

shell-db:
	@$(DOCKER_COMPOSE) -f docker-compose.yaml exec postgres psql -U postgres -d noaddx
