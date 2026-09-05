#!/usr/bin/env bash
set -euo pipefail
REPO="/mnt/e/Unreg/ICSOT Security Testbed"
cd "$REPO"
docker build -q -t ids-lab-tools -f scripts/Dockerfile.tools . 2>&1 | tail -2
echo "BUILD_OK"
