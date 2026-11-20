#!/usr/bin/env bash
# For each chaos run in results/<mode>/harness.log, report the longest gap in the
# webhook container's log during that run's scan window. The webhook logs every
# delivery, so a gap far beyond a webhook restart (~20-35 s) means the whole
# Docker VM stalled. Must run before the webhook container is recreated (its
# log is the evidence).
#   bash scripts/log-silence.sh results/final > results/final/log-silence.txt
set -euo pipefail
DIR=${1:-results/final}
DAY=$(grep -m1 -oE '"started_at" : "[0-9-]{10}' "$DIR/run-01.json" | grep -oE '[0-9-]{10}')
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

grep -E "run [0-9]+: (uploading|chaos stopped)" "$DIR/harness.log" \
  | sed -E 's/^\[([0-9:]+)\] run ([0-9]+): (uploading|chaos).*/\2 \1/' | paste -d' ' - - \
  | awk '{print $1, $2, $4}' > "$TMP/windows"
docker logs --timestamps "$(docker compose ps -q webhook)" 2>&1 \
  | grep -oE "^${DAY}T[0-9:]{8}" | sort -u > "$TMP/ts"

while read -r run start end; do
  awk -v s="${DAY}T$start" -v e="${DAY}T$end" -v r="$run" '
    $1 >= s && $1 <= e {
      split(substr($1, 12), t, ":"); x = t[1] * 3600 + t[2] * 60 + t[3]
      if (p != "") { g = x - p; if (g > max) { max = g; at = $1 } }
      p = x
    }
    END { printf "run %s scan window %s-%s: longest webhook log silence %ds (ending %s)\n",
                 r, substr(s, 12), substr(e, 12), max, substr(at, 12) }' "$TMP/ts"
done < "$TMP/windows"
