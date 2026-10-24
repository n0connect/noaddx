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
   - Click **"Create Identity"**.
   - Your browser solves a Proof-of-Work (PoW) hashcash challenge in a background Web Worker.
   - You are shown your **AccountNumber** (e.g., `k8x9F...43-chars`). **Copy and save it!**
   - Click **"Continue"** to complete registration.
   - Click **"+ Invite"** at the top left.
   - Copy the generated invite code (format: `noaddx:TOKEN_BASE64URL_WITH_FINGERPRINT`).

2. **Party B (Incognito / Second Browser Window):**
   - Open a private/incognito window to `http://localhost`.
   - Click **"Create Identity"** and complete registration for Party B.
   - Paste Party A's invite code into the **"Join with Invite"** input box and click **"Join"**.

3. **Verify & Talk:**
   - Both parties immediately see the new conversation appear in their sidebar via Server-Sent Events (SSE).
   - Click on the conversation. Notice the deterministic **"Aura"** (a distinct name and 5x5 pixel glyph derived from each other's public keys).
   - Type a message and send. Party B receives it in realtime!
   - Verify safety numbers out-of-band by clicking the contact details.
   - Test the **"Burn"** button: deleting the conversation completely wipes every ciphertext for both participants immediately.

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
