#!/usr/bin/env bash
# Reproduces every chaos number in the README, in order:
#   1. Phase 4: final design, 10 runs x 10,000 files      -> results/final
#   2. webhook log-silence check for those runs            -> results/final/log-silence.txt
#      (must run before step 3 recreates the webhook container)
#   3. Phase 5: ablation A-E, 3 runs x 10,000 files each   -> results/ablation
#   4. splice both generated summaries into README.md
# Needs: ./mvnw package -DskipTests && docker compose build
set -euo pipefail
cd "$(dirname "$0")/.."
JAR=chaos/target/chaos.jar

mkdir -p results/final results/ablation
java -Xmx256m -jar "$JAR" run --runs 10 --files 10000 --out results/final > results/final/harness.log 2>&1
bash scripts/log-silence.sh results/final > results/final/log-silence.txt
java -Xmx256m -jar "$JAR" ablation --runs 3 --files 10000 --out results/ablation > results/ablation/harness.log 2>&1
java -jar "$JAR" report --out results/final --readme README.md
java -jar "$JAR" ablation-report --out results/ablation --readme README.md
java -jar "$JAR" headline --out results/final --readme README.md
echo "all chaos runs done"
