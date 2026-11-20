#!/usr/bin/env bash
# Phase 3 demo against the full compose stack (api, 3 workers, sender, webhook).
#  0. (re)create the webhook with a 300 ms response delay so deliveries are slow enough to interrupt
#  1. upload N files (every 20th is the EICAR test string) and let workers scan them
#  2. while the sender is delivering alerts, SIGKILL it, then start it again
#  3. report: malicious verdicts vs outbox rows vs alerts accepted / duplicates rejected
set -euo pipefail
API=${API:-http://localhost:8080}
N=${N:-400}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
q()  { docker compose exec -T postgres psql -U scanqueue -d scanqueue -tAc "$1"; }
qw() { docker compose exec -T postgres psql -U scanqueue -d webhook   -tAc "$1"; }

# EICAR test string from two halves (see smoke-phase1.sh). Lives only in $TMP.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.com.txt"

# Every later `docker compose` call sees the same value, so compose never
# recreates the webhook without the delay.
export WEBHOOK_RESPONSE_DELAY_MILLIS=${WEBHOOK_RESPONSE_DELAY_MILLIS:-300}
docker compose stop sender > /dev/null 2>&1      # build an outbox backlog first
docker compose up -d --wait webhook > /dev/null 2>&1
echo "== webhook response delay: $(docker inspect "$(docker compose ps -q webhook)" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep RESPONSE_DELAY)"
echo "== uploading $N files ($((N / 20)) EICAR), sender stopped"
for i in $(seq 1 "$N"); do
  if (( i % 20 == 0 )); then f="$TMP/eicar.com.txt"; else f="$TMP/clean-$i.txt"; echo "clean file $i" > "$f"; fi
  curl -sS -o /dev/null -F "file=@$f" "$API/files" &
  (( i % 16 == 0 )) && wait
done
wait
until [[ $(q "SELECT count(*) FROM scan_job WHERE status IN ('QUEUED','RUNNING')") == "0" ]]; do sleep 0.5; done
echo "== scans done; $(q "SELECT count(*) FROM alert_outbox WHERE status = 'PENDING'") alerts pending in the outbox"

docker compose start sender > /dev/null 2>&1
until [[ $(q "SELECT count(*) FROM alert_outbox WHERE status = 'DELIVERED'") -ge 3 ]]; do sleep 0.05; done
echo "== kill -9 sender after $(q "SELECT count(*) FROM alert_outbox WHERE status = 'DELIVERED'") deliveries (requests in flight)"
docker kill -s KILL "$(docker compose ps -q sender)" > /dev/null
sleep 2
echo "== starting sender again"
docker compose start sender > /dev/null 2>&1

for _ in $(seq 1 180); do
  [[ $(q "SELECT count(*) FROM scan_job WHERE status IN ('QUEUED','RUNNING')") == "0" &&
     $(q "SELECT count(*) FROM alert_outbox WHERE status = 'PENDING'") == "0" ]] && break
  sleep 1
done

cat <<EOF
jobs DONE                 $(q "SELECT count(*) FROM scan_job WHERE status = 'DONE'") / $N
MALICIOUS verdicts        $(q "SELECT count(*) FROM scan_verdict WHERE verdict = 'MALICIOUS'")
outbox rows (DELIVERED)   $(q "SELECT count(*) FROM alert_outbox WHERE status = 'DELIVERED'")
webhook ACCEPTED          $(qw "SELECT count(*) FROM webhook.delivery_log WHERE outcome = 'ACCEPTED'")
webhook DUPLICATE_REJECTED $(qw "SELECT count(*) FROM webhook.delivery_log WHERE outcome = 'DUPLICATE_REJECTED'")
webhook distinct keys     $(qw "SELECT count(*) FROM webhook.received_alert")
keys delivered >1 time    $(qw "SELECT coalesce(string_agg(idempotency_key || ' x' || delivery_count, ', '), '-') FROM webhook.received_alert WHERE delivery_count > 1")
EOF

# Set comparison across the two databases: every malicious job must have exactly
# its own key at the webhook, and the webhook must have no other keys.
q  "SELECT 'alert:' || job_id FROM scan_verdict WHERE verdict = 'MALICIOUS' ORDER BY 1" | tr -d '\r' | sort > "$TMP/expected"
qw "SELECT idempotency_key FROM webhook.received_alert ORDER BY 1" | tr -d '\r' | sort > "$TMP/received"
echo "malicious jobs with no alert at webhook: $(comm -23 "$TMP/expected" "$TMP/received" | wc -l)"
echo "alerts at webhook with no malicious job: $(comm -13 "$TMP/expected" "$TMP/received" | wc -l)"
