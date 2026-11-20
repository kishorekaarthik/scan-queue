#!/usr/bin/env bash
# Phase 2 demo against the running compose stack (api + 3 workers).
#  1. stop the workers and upload N files (every 20th is the EICAR test string)
#  2. start 3 workers, and once they are busy draining, SIGKILL one of them
#  3. wait for the queue to drain; print verdicts, re-claimed jobs and queue events
set -euo pipefail
API=${API:-http://localhost:8080}
N=${N:-1000}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
psql() { docker compose exec -T postgres psql -U scanqueue -d scanqueue "$@"; }

# EICAR test string from two halves (see smoke-phase1.sh). Lives only in $TMP.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$TMP/eicar.com.txt"

docker compose stop worker > /dev/null 2>&1
echo "== uploading $N files ($((N / 20)) EICAR) with workers stopped"
for i in $(seq 1 "$N"); do
  if (( i % 20 == 0 )); then f="$TMP/eicar.com.txt"; else f="$TMP/clean-$i.txt"; echo "clean file $i" > "$f"; fi
  curl -sS -o /dev/null -F "file=@$f" "$API/files" &
  (( i % 16 == 0 )) && wait
done
wait

echo "== starting 3 workers"
docker compose up -d --scale worker=3 worker > /dev/null 2>&1
until [[ $(psql -tAc "SELECT count(*) FROM scan_job WHERE status = 'DONE'") -ge $((N / 10)) ]]; do sleep 0.2; done

victim=$(docker compose ps -q worker | head -1)
inflight=$(psql -tAc "SELECT count(*) FROM scan_job WHERE status = 'RUNNING' AND lease_owner LIKE '$(docker inspect -f '{{.Config.Hostname}}' "$victim")%'")
echo "== kill -9 worker ${victim:0:12} while it holds $inflight lease(s)"
docker kill -s KILL "$victim" > /dev/null
killed_at=$(psql -tAc "SELECT now()")

for _ in $(seq 1 120); do
  [[ $(psql -tAc "SELECT count(*) FROM scan_job WHERE status IN ('QUEUED','RUNNING')") == "0" ]] && break
  sleep 1
done

psql -c "SELECT status, count(*) FROM scan_job GROUP BY status ORDER BY status;"
psql -c "SELECT v.verdict, v.hash_match, v.yara_matches, count(*) FROM scan_verdict v GROUP BY 1,2,3 ORDER BY 1;"
psql -c "SELECT count(*) AS jobs, count(v.job_id) AS verdicts, count(*) FILTER (WHERE j.attempts > 1) AS reclaimed_jobs FROM scan_job j LEFT JOIN scan_verdict v ON v.job_id = j.id;"
psql -c "SELECT kind, count(*) FROM queue_event GROUP BY kind ORDER BY kind;"
echo "== re-claimed jobs: who held the lease, when it was reaped, who finished it"
psql -c "SELECT e.job_id, e.worker_id AS dead_owner, round(extract(epoch FROM e.at - '$killed_at'::timestamptz)::numeric, 1) AS reaped_s_after_kill,
                v.worker_id AS finished_by, v.claim_token, round(extract(epoch FROM j.finished_at - '$killed_at'::timestamptz)::numeric, 1) AS done_s_after_kill
         FROM queue_event e JOIN scan_verdict v USING (job_id) JOIN scan_job j ON j.id = e.job_id
         WHERE e.kind = 'LEASE_EXPIRED' ORDER BY e.at;"
