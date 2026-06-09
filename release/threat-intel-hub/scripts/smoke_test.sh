#!/usr/bin/env bash
set -euo pipefail

base="${1:-http://127.0.0.1:18080}"
curl -fsS "$base/health"
curl -fsS "$base/config" >/dev/null
curl -fsS "$base/push/ta-node/status"
