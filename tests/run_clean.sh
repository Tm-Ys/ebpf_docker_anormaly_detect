#!/bin/bash
# Clean-environment test suite: nginx + redis as quiet baselines, attacks in
# dedicated containers. No QQ/Chromium noise. Attack signals are crisp.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WINDOW=10
BASELINE_SECS=80
ATTACK_SECS=15
GAP=3
ATTACK_IMG="anomaly-clean:latest"

ATTACKS=(
  "01_recon_filescan" "02_recon_sensitive" "03_net_scan" "04_net_exfil"
  "05_crypto_mine" "06_reverse_shell" "07_priv_esc" "08_escape_probe"
)

cd "$PROJECT_DIR"
rm -f data/features.csv data/baseline.csv data/labels.csv data/features_scored.csv
mkdir -p data

# Verify prerequisites.
for c in nginx redis; do
  docker inspect "$c" >/dev/null 2>&1 || { echo "ERROR: $c not running"; exit 1; }
done
docker image inspect "$ATTACK_IMG" >/dev/null 2>&1 || { echo "ERROR: $ATTACK_IMG not found"; exit 1; }

echo "============================================================"
echo " Clean-Environment Test Suite"
echo " Baselines: nginx + redis (quiet) | Attacks: dedicated containers"
echo "============================================================"

echo "[1/5] Starting agent..."
setsid ./bin/agent --window "${WINDOW}s" --tcp-tick 5s --cpu-tick 5s --sys-tick 5s --cg-tick 10s \
  > /tmp/test_clean_agent.log 2>&1 &
disown
sleep 3

echo "[2/5] Starting baseline traffic generators..."
# nginx: steady HTTP requests (simulates real web traffic)
( while true; do curl -s -o /dev/null http://localhost:8080/ 2>/dev/null; sleep 0.3; done ) &
TRAFFIC_NGINX=$!
# redis: steady SET/GET (simulates real DB workload)
( while true; do docker exec redis redis-cli SET "k$$" "v$$" >/dev/null 2>&1; \
  docker exec redis redis-cli GET "k$$" >/dev/null 2>&1; sleep 0.2; done ) &
TRAFFIC_REDIS=$!

echo "[3/5] Collecting baseline (${BASELINE_SECS}s)..."
sleep "$BASELINE_SECS"
BASELINE_END=$(date +%Y-%m-%dT%H:%M:%S)
echo "      baseline until $BASELINE_END"

echo "[4/5] Running 8 attacks in dedicated containers..."
echo "attack_idx,attack_type,container_name,start,end" > data/labels.csv

idx=1
for atk in "${ATTACKS[@]}"; do
  CNAME="atk_${idx}_${atk}"
  START_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo -n "  [$idx/8] $atk... "

  timeout -k 5 22 docker run --rm -i --entrypoint sh --name "$CNAME" "$ATTACK_IMG" \
    -s "$ATTACK_SECS" < "$SCRIPT_DIR/attacks/${atk}.sh" >/dev/null 2>/tmp/attack_${atk}.err 2>&1 || true

  END_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo "$idx,$atk,$CNAME,$START_TS,$END_TS" >> data/labels.csv
  echo "done"
  idx=$((idx + 1))
  sleep "$GAP"
done

# Stop traffic generators.
kill $TRAFFIC_NGINX $TRAFFIC_REDIS 2>/dev/null || true

echo "      cool-down (10s)..."
sleep 10

echo "[5/5] Stopping agent + detection + visualization..."
APID=$(pgrep -x agent)
[ -n "$APID" ] && kill -INT "$APID" 2>/dev/null; sleep 2

TOTAL=$(($(wc -l < data/features.csv) - 1))
head -1 data/features.csv > data/baseline.csv
awk -F, -v c="$BASELINE_END" 'NR>1 && $2 <= c' data/features.csv >> data/baseline.csv
echo "      rows: total=$TOTAL baseline=$(($(wc -l < data/baseline.csv)-1))"

export PATH="$HOME/.local/bin:$PATH"
.venv/bin/python detect/detect.py data/features.csv --train data/baseline.csv --contamination 0.1 2>&1 | tail -20

echo ""
echo "============================================================"
.venv/bin/python "$SCRIPT_DIR/report_clean.py" data/features_scored.csv data/labels.csv

echo ""
.venv/bin/python detect/visualize.py data/features_scored.csv data/labels.csv 2>&1 | grep -E "saved|done"
echo ""
echo "Done."
