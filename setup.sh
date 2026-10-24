#!/bin/sh
set -e

# setup.sh - Legacy wrapper delegating to Makefile
echo "[INFO] Delegating to 'make setup'..."
exec make setup "$@"
