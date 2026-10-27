#!/usr/bin/env bash
# Runs the server in the foreground. Config: DATABASE_URL, JWT_SECRET, HOST, PORT, EXTRA_PORT (SPEC.md).
set -euo pipefail
ulimit -n "$(ulimit -Hn)"   # a no-op under systemd's LimitNOFILE; raises a login shell's soft limit of 1024
exec "$(cd "$(dirname "$0")" && pwd)/target/release/feed-server"
