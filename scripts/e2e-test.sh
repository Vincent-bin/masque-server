#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# 1. Generate self-signed certs if missing.
bash scripts/gen-certs.sh

# 2. Build images.
docker compose -f tests/e2e/compose.yml build

# 3. Run the test suite.
EXIT_CODE=0
docker compose -f tests/e2e/compose.yml up \
    --abort-on-container-exit \
    --exit-code-from test || EXIT_CODE=$?

# 4. Clean up.
docker compose -f tests/e2e/compose.yml down --volumes --remove-orphans

exit "$EXIT_CODE"
