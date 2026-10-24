# Troubleshooting Guide

This guide details real-world pitfalls, diagnostic commands, and immediate copy-paste solutions for common development, deployment, and cryptographic situations.

---

## Quick Diagnostic Checklist

| Error Symptom | Root Cause | Quick Solution |
|---|---|---|
| `OpenSSL >= 3.2.0 is required (LibreSSL is not supported)` | macOS default `/usr/bin/openssl` is Apple LibreSSL. | `export PATH="$(brew --prefix openssl@3)/bin:$PATH"` |
| `TypeError: Cannot read properties of undefined (reading 'subtle')` | Accessing via non-secure HTTP on IP address (e.g. `192.168.x.x`). | Use `http://localhost` or configure HTTPS/TLS. |
| `bash: \r: invalid command` | Git on Windows converted script line endings to CRLF. | `dos2unix Makefile setup.sh run.sh` |
| `bind: address already in use (port 80 or 5432)` | Port occupied by another local service (Apache, local Postgres). | `sudo lsof -i :80` or remap ports in `docker-compose.yaml`. |
| `failed to connect to host=localhost:5432` inside container | Container tries connecting to itself instead of Postgres service. | Set `DOCKER_DB_HOST=postgres` in `.env`. |
| Backend container exits with code `137` | Linux Out-Of-Memory (OOM) Killer killed backend during Argon2id. | Reduce `ARGON2_MEMORY_KIB=32768` and enable host swap. |
| Session lost immediately upon browser reload | Private/Incognito mode blocked IndexedDB storage. | Normal window or save AccountNumber to log in again. |

---

## 1. macOS: LibreSSL Rejection

### Symptom
Running `make setup` on macOS exits with:
```text
ERROR: OpenSSL >= 3.2.0 is required (LibreSSL is not supported).
```

### Cause
macOS ships with `/usr/bin/openssl`, which is actually Apple's LibreSSL fork (v3.3.6). `make setup` requires real OpenSSL >= 3.2.0. Even after `brew install openssl@3`, Homebrew keeps OpenSSL "keg-only" to avoid breaking Apple system utilities.

### Immediate Fix
Copy and paste this into your terminal:
```bash
brew install openssl@3
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
make setup
```
To persist this across all future terminal sessions:
```bash
echo 'export PATH="$(brew --prefix openssl@3)/bin:$PATH"' >> ~/.zshrc
```

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
Error response from daemon: driver failed programming external connectivity on endpoint noaddress-frontend:
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
The `noaddress-backend` container restarts repeatedly. Logs show:
```text
failed to connect to `host=localhost user=postgres database=noaddress`: dial tcp 127.0.0.1:5432: connect: connection refused
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
