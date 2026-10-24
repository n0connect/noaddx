# Troubleshooting Guide

This guide details real-world pitfalls, diagnostic commands, and immediate copy-paste solutions for common development, deployment, and cryptographic situations.

---

## Quick Diagnostic Checklist

| Error Symptom | Root Cause | Quick Solution |
|---|---|---|
| `Pool overlaps with other one on this address space` | Another Docker network already uses `172.29.73.0/24`. | Pick a free range: set `COMPOSE_SUBNET` and `PROXY_IP` in `.env`. |
| Everyone gets `429` on login or registration | The backend does not trust the proxy in front of it, so all users share its address. | Set `TRUSTED_PROXIES` to that proxy's address (see section 1). |
| `TypeError: Cannot read properties of undefined (reading 'subtle')` | Accessing via non-secure HTTP on IP address (e.g. `192.168.x.x`). | Use `http://localhost` or configure HTTPS/TLS. |
| `bash: \r: invalid command` | Git on Windows converted script line endings to CRLF. | `dos2unix Makefile setup.sh run.sh` |
| `bind: address already in use (port 80 or 5432)` | Port occupied by another local service (Apache, local Postgres). | `sudo lsof -i :80` or remap ports in `docker-compose.yaml`. |
| `failed to connect to host=localhost:5432` inside container | Container tries connecting to itself instead of Postgres service. | Set `DOCKER_DB_HOST=postgres` in `.env`. |
| Backend container exits with code `137` | Linux Out-Of-Memory (OOM) Killer killed backend during Argon2id. | Reduce `ARGON2_MEMORY_KIB=32768` and enable host swap. |
| Session lost immediately upon browser reload | Private/Incognito mode blocked IndexedDB storage. | Normal window or save AccountNumber to log in again. |

---

## 1. Docker Network Range and the Trusted Proxy

### Symptom
`make up` fails with `Pool overlaps with other one on this address space`, or, behind your own reverse proxy, every user receives `429 Too Many Requests` after a handful of logins.

### Cause
Rate limits are keyed by the client address. nginx reaches the backend from a fixed address on the compose network (`PROXY_IP`, default `172.29.73.10` in `COMPOSE_SUBNET` `172.29.73.0/24`), and the backend accepts `X-Forwarded-For`/`X-Real-IP` only from that address (`TRUSTED_PROXIES`). If the range is taken by another Docker network, compose cannot create it; if another proxy sits in front and is not trusted, every request appears to come from that proxy and all users share one rate-limit bucket.

### Fix
1. **Range collision:** choose a free private range in `.env`, keeping the proxy address inside it:
   ```bash
   COMPOSE_SUBNET=172.31.200.0/24
   PROXY_IP=172.31.200.10
   ```
2. **Your own reverse proxy in front of nginx:** list its address (or CIDR) in `TRUSTED_PROXIES`, together with nginx's: `TRUSTED_PROXIES=172.29.73.10,10.0.0.5`. The backend reads `X-Forwarded-For` from the right and takes the first address that is not a trusted proxy.

---

## 2. WebCrypto "crypto.subtle is undefined" (Secure Context)

### Symptom
Clicking **"Create Identity"** or **"Login"** displays no reaction or logs a JavaScript error in the browser developer console:
```text
TypeError: Cannot read properties of undefined (reading 'subtle')
```

### Cause
W3C WebCrypto API specification requires a **Secure Context**. Modern browsers automatically disable `window.crypto.subtle` when accessing via unencrypted HTTP on remote IP addresses (such as `http://192.168.1.45/` or `http://your-server-ip/`).

### Fix
1. **For Local Testing:** Always navigate to **`http://localhost`** or **`http://127.0.0.1`** (browsers treat loopback addresses as secure contexts even over HTTP).
2. **For Remote / LAN Testing:** You **must** terminate TLS with a reverse proxy or generate a self-signed / Let's Encrypt SSL certificate.

---

## 3. Windows / WSL2: CRLF Line-Ending Failure

### Symptom
Inside WSL2, executing `make` or shell scripts fails with:
```text
bash: \r: invalid command
```

### Cause
When cloned using Git for Windows, text files have Unix `LF` line-endings replaced with Windows `CRLF` (`\r\n`). Bash cannot parse carriage return characters.

### Immediate Fix
Inside your WSL terminal, run:
```bash
sed -i 's/\r$//' Makefile setup.sh run.sh
# Or using dos2unix:
sudo apt-get install -y dos2unix
dos2unix Makefile setup.sh run.sh
```
To prevent Git from doing this in future checkouts:
```bash
git config --global core.autocrlf input
```

---

## 4. Port Conflict: Port 80 or 5432 Already in Use

### Symptom
Running `make up` fails during Docker startup:
```text
Error response from daemon: driver failed programming external connectivity on endpoint noaddx-frontend:
Bind for 0.0.0.0:80 failed: port is already allocated
```

### Cause
Another web server (Nginx, Apache, IIS) or database server (local PostgreSQL) is already running on port 80 or 5432.

### Diagnosis & Fix
1. **Find what is holding the port:**
   ```bash
   # On macOS or Linux:
   sudo lsof -i :80
   sudo lsof -i :5432
   ```
2. **Option A: Stop the conflicting service:**
   ```bash
   # Stop local Apache / Nginx:
   sudo systemctl stop nginx
   sudo systemctl stop apache2
   # Stop local Postgres:
   sudo systemctl stop postgresql
   ```
3. **Option B: Remap frontend port in `docker-compose.yaml`:**
   Change line 95 of `docker-compose.yaml`:
   ```yaml
   ports:
     - "8080:80"   # Access via http://localhost:8080
   ```

---

## 5. Docker Backend Database Connection Failure

### Symptom
The `noaddx-backend` container restarts repeatedly. Logs show:
```text
failed to connect to `host=localhost user=postgres database=noaddx`: dial tcp 127.0.0.1:5432: connect: connection refused
```

### Cause
In Docker Compose networking, `localhost` inside the `backend` container refers to the container itself, not the `postgres` container.

### Fix
`docker-compose.yaml` is configured to use `${DOCKER_DB_HOST:-postgres}`. Ensure `DOCKER_DB_HOST` in `.env` is set to `postgres` (the Docker service name):
```ini
DOCKER_DB_HOST=postgres
```
*Note: Host-based development (e.g., `go test -p 1 -tags=test ./...` running directly on your laptop) continues to use `DB_HOST=localhost` because Docker exposes port 5432 to `127.0.0.1:5432`.*

---

## 6. Out-Of-Memory (OOM) Crash on Low-RAM VPS

### Symptom
Backend exits abruptly with exit code `137` (SIGKILL by Linux kernel OOM killer). `dmesg` reports:
```text
Out of memory: Killed process 1234 (main) total-vm:854320kB, anon-rss:524100kB
```

### Cause
Argon2id password hashing allocates `64 MiB` of RAM per concurrent registration or login request. On a 512MB or 1GB VPS, a burst of 3-4 concurrent users can exhaust system memory.

### Fix
Adjust Argon2id settings in `.env` for low-memory environments:
```ini
ARGON2_MEMORY_KIB=32768
ARGON2_TIME=2
ARGON2_PARALLELISM=1
```
Add a 2GB swap file to prevent kernel kills:
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 7. Reloading Browser Causes "Session Ended - Log In Again"

### Symptom
After reloading or opening a new tab, the user is unexpectedly returned to the Login screen.

### Cause
The browser is operating in **Incognito / Private Browsing mode** or **Tor Browser Strict mode**, where IndexedDB write permissions are disabled or wiped on tab close.
In this mode, `keystore.js` keeps private keys in volatile memory only.

### Handling
- If privacy settings block IndexedDB, keep your 43-character `AccountNumber` copied in a password manager.
- You can log back in at any time: the derived keys and conversations will be restored.

---

### Next Steps:
- Review [**Testing & Development**](../development/testing-and-contributing.md) for automated test suites.
- Read [**Configuration & Tuning**](../operations/configuration-and-tuning.md) for full parameter references.
