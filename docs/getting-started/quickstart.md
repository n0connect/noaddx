# Quick Start Guide

Get **noaddx.** up and running on your local machine in under 3 minutes.

---

## Prerequisites Checklist

Before running any script, make sure your machine has:

- **Docker & Docker Compose** (Docker Compose v2 `docker compose` or v1 `docker-compose`)
- **openssl** (any version; only `openssl rand` is used, so the LibreSSL that macOS ships is fine)
- *(Optional)* **Go 1.26+** and **Node.js 20+** if you intend to run unit tests natively without Docker.

---

## 3-Step Setup

### Step 1: Configure Environment

Run `make setup` to generate cryptographic master keys, peppers, and default configuration in `.env`:

```bash
make setup
```

**What happens here:**
- Checks system dependencies (Docker Compose, openssl).
- Generates a 256-bit CSPRNG `JWT_SECRET`, `ACCOUNT_LOOKUP_PEPPER` and `MASTER_KEY_ACTIVE`, plus a random `DB_PASSWORD`.
- Populates `.env` with secure default values and strict permissions (`0600`).

---

### Step 2: Build and Start Containers

Start all services (PostgreSQL, Go backend, and Nginx reverse proxy):

```bash
make up
```

To clean all previous containers and run a fresh build:
```bash
make clean && make up
```

To run the containerized test suite first and only launch if all tests pass:
```bash
make test-run
```

**Expected output:**
```text
[INFO] Building...
[INFO] Starting services...
[OK] Services running
NAME                 IMAGE                     STATUS
noaddx-backend    noaddx-backend         Up (healthy)
noaddx-frontend   noaddx-frontend        Up
noaddx-postgres   postgres:15-alpine        Up (healthy)
```

---

### Step 3: Open the Web Application

Open your browser and navigate to:

**[http://localhost](http://localhost)**

> [!CAUTION]
> **WebCrypto Secure Context Requirement:**
> Always access the application via `http://localhost` or `http://127.0.0.1`.
> If you access it via a local network IP (e.g., `http://192.168.1.100`), modern browsers will disable `window.crypto.subtle` because it is not considered a Secure Context, causing registration and messaging to fail! For remote access, you must configure TLS/HTTPS.

---

## 60-Second Walkthrough: Two-Party Chat

To test end-to-end encryption locally between two parties:

1. **Party A (Normal Window):**
   - Click **new identity**, then **copy**.
   - Your browser solves a Proof-of-Work (PoW) hashcash challenge in a background Web Worker while the account number scrambles; then your **AccountNumber** appears (43 characters) and is copied to the clipboard. **Save it in a password manager:** it is the only way back into this identity.
   - Click **continue →** to create the account (a second, fresh PoW).
   - Click **+ invite**. Every invite costs one PoW too: the code scrambles for a few seconds, then appears (`noaddx:` + 43 characters) and is copied.

2. **Party B (Incognito / Second Browser Window):**
   - Open a private window to `http://localhost` and create a second identity the same way.
   - Click **join**, paste Party A's invite code and press **join**.

3. **Verify & Talk:**
   - The conversation appears for both parties at once (Server-Sent Events).
   - Open it. Each side shows the other's **aura**: a name and a 5x5 glyph derived from the peer's public key.
   - Send a message; the other side receives it in realtime.
   - Click **verify** and compare the safety number with your peer over another channel, then **mark as verified**.
   - **burn** erases the conversation and every ciphertext for both participants.
   - **delete** (next to logout) erases the whole identity: paste the account number to confirm. Every conversation is burned for both sides and the number can never log in again.

> [!TIP]
> **Over Tor:** `make onion` publishes the same app as a Tor onion service and `make onion-address` prints its address; open it in Tor Browser (security level Standard). See [**Onion Service (Tor)**](../operations/onion-service.md).

---

## Sanity & Health Checks

Verify your deployment status from the terminal:

```bash
# Check running containers and health status
docker compose ps

# Verify backend health endpoint (should return 401 Unauthorized, proving routing and middleware are active)
curl -i http://localhost:8080/api/v2/me

# View live backend logs
docker compose logs -f backend

# View live Nginx proxy logs
docker compose logs -f frontend
```

---

## Stopping and Cleaning Up

```bash
# Stop all services gracefully
docker compose down

# Stop and remove all persistent database volumes
docker compose down -v
```

---

### Next Steps:
- Learn about OS-specific setups and CPU architecture notes in [**Installation & Platforms**](installation-and-platforms.md).
- Understand how your messages are encrypted in [**Cryptography Specification**](../security/cryptography.md).
- Review [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md) if you hit any unexpected issues.
