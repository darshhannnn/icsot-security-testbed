#!/usr/bin/env bash
cd "/mnt/e/Unreg/ICSOT Security Testbed/GRFICSv3" || exit 1
for c in plc HMI EWS simulation router; do
  echo "===== $c ====="
  docker inspect -f 'Running={{.State.Running}} ExitCode={{.State.ExitCode}} Error={{.State.Error}} OOM={{.State.OOMKilled}} Restarts={{.RestartCount}}' "$c" 2>/dev/null
  docker logs --tail 15 "$c" 2>&1 | tail -15
done
