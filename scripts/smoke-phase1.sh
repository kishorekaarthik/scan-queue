#!/usr/bin/env bash
# Phase 1 smoke test against the running compose stack:
# upload a harmless file and the EICAR test string, then show the job rows and stored objects.
set -euo pipefail
API=${API:-http://localhost:8080}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "hello, scan-queue" > "$TMP/hello.txt"
# EICAR anti-malware TEST string (not malware). Assembled from two halves so this
# script itself is not flagged by antivirus on the developer's machine.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.com.txt"

for f in hello.txt eicar.com.txt; do
  echo "== POST /files ($f)"
  curl -sS -i -F "file=@$TMP/$f" "$API/files" | grep -iE '^(HTTP|Location)|jobId'
done

echo "== GET /stats"
curl -sS "$API/stats"; echo

echo "== scan_job rows"
docker compose exec -T postgres psql -U scanqueue -d scanqueue -c \
  "SELECT id, object_key, original_filename, size_bytes, status, attempts, max_attempts, lease_expires_at FROM scan_job ORDER BY created_at DESC LIMIT 5;"
