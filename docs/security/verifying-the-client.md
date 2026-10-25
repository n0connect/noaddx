# Verifying the Client

All of noaddx.'s cryptography runs in JavaScript that the server sends to the browser. A
compromised or coerced server could send a different script and read everything, so "the
server never sees plaintext" holds only if the served client is the released one. Every
release lets anyone check that, without trusting the server or its operator.

## What a release carries

The release workflow (`.github/workflows/release.yml`) runs on each `noaddx-*-vX.Y.Z` tag and
attaches two files:

| File | Contents |
|---|---|
| `frontend.sha256` | SHA-256 of every file the frontend serves (`make manifest`: tracked files only) |
| `frontend.sha256.sigstore.json` | Sigstore keyless signature of that list, issued to this repository's release workflow for that tag |

There is no signing key to steal or lose: the signature is bound to the GitHub workflow
identity and recorded in Sigstore's public transparency log.

## Checking an instance

1. Download both files from the release you expect the instance to run.
2. Check the list is the one the release workflow signed:

   ```bash
   cosign verify-blob --bundle frontend.sha256.sigstore.json \
     --certificate-identity-regexp '^https://github\.com/n0connect/noaddx/\.github/workflows/release\.yml@refs/tags/noaddx-' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     frontend.sha256
   ```

3. Check the instance serves exactly those bytes:

   ```bash
   make verify-frontend URL=https://chat.example MANIFEST=frontend.sha256
   # an onion service, through Tor Browser's SOCKS proxy:
   make verify-frontend URL=http://<address>.onion CURL_OPTS="--socks5-hostname 127.0.0.1:9150"
   ```

   Any file that differs is printed as `[MISMATCH] /path` and the command fails.

## What this does and does not prove

It proves what the instance served to **this** request. A targeted server could serve the
released client to verifiers and a modified one to a chosen user. Closing that gap needs a
client the browser does not fetch from the server each time (a packaged client or a
verifying extension), which is on the roadmap.
