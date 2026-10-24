# Installation & Cross-Platform Guide

This guide provides deep, situation-aware setup instructions across **macOS (Apple Silicon & Intel)**, **Linux (Debian/Ubuntu, RHEL/Fedora, Arch)**, and **Windows (WSL2)**, as well as considerations for **arm64 vs. amd64** CPU architectures and hardware constraints.

---

## Hardware & Architecture Overview

`noaddx.` is engineered to be portable and lightweight:
- **Backend:** Pure Go 1.21+ built with `CGO_ENABLED=0` (no CGO, no OpenSSL link-time dependency in the Go binary).
- **Frontend:** Vanilla modern JavaScript using the native W3C WebCrypto API (no webpack, no npm bundle dependencies for runtime).
- **Docker Images:** `golang:1.21-bookworm`, `postgres:15-alpine`, and `nginx:alpine` have official multi-architecture support for both `linux/amd64` and `linux/arm64`.

| Architecture | Platform Examples | Build Support | Performance Notes |
|---|---|---|---|
| **`amd64` (x86_64)** | Intel Core/Xeon, AMD Ryzen/EPYC | Native | Full AVX2 / SHA extensions acceleration |
| **`arm64` (aarch64)** | Apple Silicon (M1-M4), AWS Graviton, Raspberry Pi 4/5 | Native | Hardware accelerated SHA-256 and AES |

---

## macOS Installation (Apple Silicon & Intel)

### The LibreSSL vs. OpenSSL >= 3.2.0 Trap

macOS ships `/usr/bin/openssl` by default, but it is actually **Apple's LibreSSL fork** (typically LibreSSL 3.3.6).
`make setup` strictly enforces **OpenSSL >= 3.2.0** to generate high-entropy cryptographic seeds and will abort with:
```text
ERROR: OpenSSL >= 3.2.0 is required (LibreSSL is not supported).
```

Furthermore, Homebrew installs `openssl@3` as **"keg-only"**, meaning Homebrew intentionally **does NOT symlink it** into `/usr/local/bin` or `/opt/homebrew/bin` to prevent breaking Apple system tools.

### Fix for macOS (Copy & Paste)

1. **Install OpenSSL 3 via Homebrew:**
   ```bash
   brew install openssl@3
   ```

2. **Temporarily export to current terminal session:**
   ```bash
   export PATH="$(brew --prefix openssl@3)/bin:$PATH"
   ```

3. **Permanently persist in your shell profile:**
   - **For Zsh (default on macOS):**
     ```bash
     echo 'export PATH="$(brew --prefix openssl@3)/bin:$PATH"' >> ~/.zshrc
     source ~/.zshrc
     ```
   - **For Bash:**
     ```bash
     echo 'export PATH="$(brew --prefix openssl@3)/bin:$PATH"' >> ~/.bash_profile
     source ~/.bash_profile
     ```

4. **Verify the active OpenSSL version:**
   ```bash
   openssl version
   # Must output: OpenSSL 3.2.x (or higher)
   ```

### Docker Desktop on macOS
- Ensure Docker Desktop is running.
- **Apple Silicon Tip:** In Docker Desktop Settings -> *General*, ensure **"Use Rosetta for x86/amd64 emulation on Apple Silicon"** is enabled if cross-compiling, but for `noaddx.`, let Docker build natively for `linux/arm64` (fastest compilation and execution).

---

## Linux Installation (Debian, Ubuntu, RHEL, Fedora, Arch)

### 1. Ubuntu / Debian

```bash
# Update repositories
sudo apt-get update

# Install prerequisites
sudo apt-get install -y openssl curl git ca-certificates

# Install Docker Engine & Docker Compose Plugin
sudo apt-get install -y docker.io docker-compose-v2
```

> [!WARNING]
> **Ubuntu 22.04 LTS (Jammy) Note:**
> Ubuntu 22.04 LTS ships with OpenSSL `3.0.2`. `make setup` requires `>= 3.2.0`.
> If you are on Ubuntu 22.04, upgrade OpenSSL or use Ubuntu 24.04 LTS / Debian 12 (Bookworm).

### 2. Fedora / Red Hat / Rocky Linux

```bash
sudo dnf install -y openssl git curl make
sudo dnf install -y docker-ce docker-compose-plugin
sudo systemctl enable --now docker
```

### 3. Arch Linux

```bash
sudo pacman -Syu --needed openssl git docker docker-compose make
sudo systemctl enable --now docker
```

### Critical Linux Permission Check (Non-Root Docker)

If running `make up` fails with `permission denied while trying to connect to the Docker daemon socket`:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Apply group changes immediately (or logout and log back in)
newgrp docker

# Verify docker runs without sudo
docker ps
```

---

## Windows 10 / 11 Installation (via WSL2)

`noaddx.` relies on a standard Makefile, Linux-targeted Docker images, and Unix socket conventions. **Running directly on native Windows PowerShell/CMD is not supported; you MUST use WSL2.**

### The CRLF vs. LF Line-Ending Trap

When Git clones a repository on Windows, it often automatically converts Unix line endings (`LF`) to Windows carriage returns (`CRLF`).
If shell scripts or Makefile recipes contain `\r`, commands may fail with errors such as:
```text
bash: \r: invalid command
```

### Complete Windows Setup Procedure

1. **Install WSL2 (if not already installed):**
   Open PowerShell as Administrator:
   ```powershell
   wsl --install -d Ubuntu-24.04
   ```
   Restart your PC if prompted.

2. **Configure Git in WSL2 to preserve Unix line endings:**
   Inside your WSL2 terminal:
   ```bash
   git config --global core.autocrlf input
   ```

3. **If you already cloned the repo and have CRLF errors:**
   Fix line endings with one command inside WSL:
   ```bash
   sudo apt-get install -y dos2unix
   dos2unix Makefile setup.sh run.sh
   ```

4. **Install Docker Desktop for Windows:**
   - In Docker Desktop Settings -> *General*, check **"Use the WSL 2 based engine"**.
   - In Settings -> *Resources* -> *WSL Integration*, enable integration with your installed distribution (e.g., `Ubuntu-24.04`).

5. **Execute Setup and Launch inside WSL2:**
   ```bash
   make setup
   make up
   ```
   Access the app from your Windows browser at `http://localhost`.

---

## Memory Sizing & VPS Optimization (Argon2id)

`noaddx.` uses memory-hard Argon2id key derivation on the server to protect derived auth keys:
- **Default configuration:** `ARGON2_MEMORY_KIB=65536` (64 MiB per hash), `ARGON2_PARALLELISM=2` (or `4`).
- **RAM Impact:** Each concurrent registration or login attempt allocates approximately **64-128 MiB of RAM** during the ~200ms calculation.

### Low-RAM Budget VPS Profile (512 MB - 1 GB RAM)

If deploying to a minimal VPS (e.g., a $4/month VPS with 1 GB RAM), concurrent registration spikes can trigger the Linux Out-Of-Memory (OOM) Killer.

Tune `.env` with these hardened low-memory parameters:

```ini
# Safe for 1GB RAM machines (prevents OOM crashes while maintaining high security)
ARGON2_MEMORY_KIB=32768
ARGON2_TIME=2
ARGON2_PARALLELISM=1
```

And add a 2GB swapfile on your Linux host:
```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Local Host Development (Without Docker)

If you prefer running the Go server and tests natively on your host machine:

### 1. Go Toolchain
```bash
# Verify Go version >= 1.21
go version
```
Dependencies are managed via Go modules (`backend/go.mod`). Run:
```bash
cd backend
go mod download
```

### 2. Node.js (For WebCrypto Client Derivation Tests)
Node.js 20+ has native support for `node:crypto` with WebCrypto X25519 and `node --test`:
```bash
node -v # Must be >= 20.0.0
node --test frontend/tests/
```
No `package.json` or `npm install` is required; it executes against Node's built-in test runner.

---

### Next Steps:
- Read [**System Architecture**](../architecture/system-overview.md) to understand how data flows.
- Review [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md) if you encounter port conflicts or network issues.
