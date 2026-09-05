#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y git git-lfs docker.io docker-compose-plugin

if [ ! -d GRFICSv3 ]; then
  git clone https://github.com/Fortiphyd/GRFICSv3.git
fi

cd GRFICSv3
./build.sh
docker compose up -d

echo "GRFICSv3 should be available at http://localhost"

