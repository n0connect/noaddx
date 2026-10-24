#!/bin/sh
set -e

# run.sh - Legacy wrapper delegating to Makefile
case "${1:-}" in
  --test)
    exec make test
    ;;
  --test-run)
    exec make test-run
    ;;
  --clean)
    exec make clean
    ;;
  -h|--help)
    exec make help
    ;;
  *)
    exec make up
    ;;
esac
