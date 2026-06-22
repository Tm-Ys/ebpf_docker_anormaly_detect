#!/bin/bash
# Dedicated-container test suite: each attack runs in its own fresh container
# (from anomaly-base image). Attack = 100% of the signal, not diluted by
# napcat's 33M baseline. More realistic detection scenario: "unknown container
# with anomalous behavior appeared."

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WINDOW=10
BASELINE_SECS=80
ATTACK_SECS=15
GAP=5

ATTACKS=(
  "01_recon_filescan" "02_recon_sensitive" "03_net_scan" "04_net_exfil"
  "05_crypto_mine" "06_reverse_shell" "07_priv_esc" "08_escape_probe"
)

cd "$PROJECT_DIR"
rm -f data/features.csv data/baseline.csv data/labels.csv data/features_scored.csv
mkdir -p data

# Verify base image exists.
if ! docker image inspect anomaly-base:latest >/dev/null 2>&1; then
  echo "ERROR: anomaly-base image not found. Run: docker commit napcat anomaly-base:latest"
  exit 1
fi

echo "============================================================"
echo " Dedicated-Container Test Suite"
echo " Baseline containers: napcat + astrbot | Attack image: anomaly-base"
echo "============================================================"

echo "[1/4] Starting agent..."
setsid ./bin/agent --window "${WINDOW}s" --tcp-tick 5s --cpu-tick 5s --sys-tick 5s --cg-tick 10s \
  > /tmp/test_dedicated_agent.log 2>&1 &
disown
sleep 3

echo "[2/4] Baseline (${BASELINE_SECS}s, napcat + astrbot normal)..."
sleep "$BASELINE_SECS"
BASELINE_END=$(date +%Y-%m-%dT%H:%M:%S)
echo "      baseline until $BASELINE_END"

echo "[3/4] Running 8 attacks in dedicated containers..."
echo "attack_idx,attack_type,container_name,start,end" > data/labels.csv

idx=1
for atk in "${ATTACKS[@]}"; do
  CNAME="attacker_${idx}_${atk}"
  START_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo "  [$idx/8] $atk → container $CNAME (${ATTACK_SECS}s)"

  # Run attack in a FRESH container. --entrypoint sh overrides napcat's
  # entrypoint (which would start QQ/Chromium). timeout caps wall time.
  timeout -k 5 25 docker run --rm -i --entrypoint sh --name "$CNAME" anomaly-base:latest \
    -s "$ATTACK_SECS" < "$SCRIPT_DIR/attacks/${atk}.sh" \
    >/dev/null 2>/tmp/attack_${atk}.err || true

  END_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo "$idx,$atk,$CNAME,$START_TS,$END_TS" >> data/labels.csv
  idx=$((idx + 1))
  sleep "$GAP"
done

echo "      cool-down (10s)..."
sleep 10

echo "[4/4] Detection + visualization..."
APID=$(pgrep -x agent)
[ -n "$APID" ] && kill -INT "$APID" 2>/dev/null; sleep 2

TOTAL=$(($(wc -l < data/features.csv) - 1))
head -1 data/features.csv > data/baseline.csv
awk -F, -v c="$BASELINE_END" 'NR>1 && $2 <= c' data/features.csv >> data/baseline.csv
echo "      total rows: $TOTAL  baseline: $(($(wc -l < data/baseline.csv)-1))"

export PATH="$HOME/.local/bin:$PATH"
.venv/bin/python detect/detect.py data/features.csv --train data/baseline.csv --contamination 0.12 2>&1 | tail -25

echo ""
echo "============================================================"
echo " Per-Attack Detection Report"
echo "============================================================"
.venv/bin/python "$SCRIPT_DIR/report_dedicated.py" data/features_scored.csv data/labels.csv

echo ""
echo "[plots] generating visualization..."
.venv/bin/python detect/visualize.py data/features_scored.csv data/labels.csv
echo ""
echo "Done."
