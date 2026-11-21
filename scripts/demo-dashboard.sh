#!/usr/bin/env bash
# ~2-minute live chaos demo for recording the dashboard.
#   1. starts the stack (5 workers, 1 sender, webhook with 200 ms latency)
#   2. tells you to open http://localhost:8080/ and start recording
#   3. runs one chaos round: 4,000 uploads (5% EICAR) while workers and the
#      sender are SIGKILLed, the webhook is restarted, and lease holders are
#      frozen into zombies, then drains and verifies
# Results go to results/demo/ (not committed). Stop with: docker compose down
# Needs: ./mvnw package -DskipTests && docker compose build
set -euo pipefail
cd "$(dirname "$0")/.."
FILES=${FILES:-4000}
WAIT=${WAIT:-15}
export WEBHOOK_RESPONSE_DELAY_MILLIS=200

docker compose up -d --scale worker=5 > /dev/null
echo "waiting for the API..."
until curl -sf http://localhost:8080/actuator/health > /dev/null; do sleep 1; done

echo
echo "  Open http://localhost:8080/ and start recording."
for i in $(seq "$WAIT" -1 1); do printf "\r  chaos starts in %2d s " "$i"; sleep 1; done
echo
# PAUSE_AFTER_RESET_MS: hold a few seconds on the zeroed dashboard before uploads start
java -Xmx256m -jar chaos/target/chaos.jar run --runs 1 --files "$FILES" --out results/demo \
  --pause-after-reset-ms "${PAUSE_AFTER_RESET_MS:-3000}"
echo
echo "Done. Checks and numbers: results/demo/summary.md"
echo "The dashboard stays live; stop the stack with: docker compose down"
