#!/bin/bash
# Test suite orchestrator: runs baseline collection, 8 attack types, detection,
# and produces a labeled detection-rate report.
#
# Usage: tests/run_suite.sh [target_container]
#
# Default target: napcat (has rich tooling + known baseline behavior).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="${1:-napcat}"
WINDOW=10           # feature vector window (seconds)
BASELINE_SECS=60    # baseline collection
ATTACK_SECS=20      # per-attack duration
COOLDOWN_SECS=10    # post-attack cool-down

ATTACKS=(
  "01_recon_filescan"
  "02_recon_sensitive"
  "03_net_scan"
  "04_net_exfil"
  "05_crypto_mine"
  "06_reverse_shell"
  "07_priv_esc"
  "08_escape_probe"
)

cd "$PROJECT_DIR"

echo "============================================================"
echo " Container Anomaly Detection Test Suite"
echo " Target container: $TARGET"
echo " Window: ${WINDOW}s | Baseline: ${BASELINE_SECS}s | Attack: ${ATTACK_SECS}s each"
echo "============================================================"

# Clean slate.
rm -f data/features.csv data/baseline.csv data/labels.csv data/features_scored.csv
mkdir -p data

# Start agent.
echo "[1/4] Starting agent..."
setsid ./bin/agent \
  --window "${WINDOW}s" \
  --tcp-tick 5s --cpu-tick 5s --sys-tick 5s --cg-tick 10s \
  > /tmp/test_suite_agent.log 2>&1 &
AGENT_BG=$!
disown
sleep 3

# Verify agent is running.
if ! kill -0 "$AGENT_BG" 2>/dev/null; then
  echo "ERROR: agent failed to start. Log:"
  tail -20 /tmp/test_suite_agent.log
  exit 1
fi
echo "      agent pid=$AGENT_BG"

# Baseline collection.
echo "[2/4] Collecting baseline (${BASELINE_SECS}s)..."
sleep "$BASELINE_SECS"
BASELINE_END=$(date +%Y-%m-%dT%H:%M:%S)
echo "      baseline collected until $BASELINE_END"

# Attack phase.
echo "[3/4] Running ${#ATTACKS[@]} attack types..."
LABELS_FILE="data/labels.csv"
echo "attack_idx,attack_type,start,end" > "$LABELS_FILE"

idx=1
for atk in "${ATTACKS[@]}"; do
  START_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo "  [$idx/${#ATTACKS[@]}] $atk (${ATTACK_SECS}s)..."

  # Pipe the attack script into the target container. Each attack runs for
  # ATTACK_SECS seconds. We capture stderr to see if it errored.
  docker exec -i "$TARGET" sh -s "$ATTACK_SECS" \
    < "$SCRIPT_DIR/attacks/${atk}.sh" 2>/tmp/attack_${atk}.err \
    || echo "    (attack exited non-zero — may be expected for EPERM cases)"

  END_TS=$(date +%Y-%m-%dT%H:%M:%S)
  echo "$idx,$atk,$START_TS,$END_TS" >> "$LABELS_FILE"
  idx=$((idx + 1))

  # Brief gap between attacks so windows don't bleed.
  sleep 2
done

# Cool-down window (captures post-attack return to normal).
echo "      cool-down (${COOLDOWN_SECS}s)..."
sleep "$COOLDOWN_SECS"

# Stop agent.
echo "[4/4] Stopping agent + running detection..."
APID=$(pgrep -x agent)
if [ -n "$APID" ]; then
  kill -INT "$APID" 2>/dev/null || true
  sleep 2
fi

# Verify data collected.
TOTAL_ROWS=$(($(wc -l < data/features.csv) - 1))
echo "      collected $TOTAL_ROWS feature rows"

# Split baseline vs all.
head -1 data/features.csv > data/baseline.csv
awk -F, -v cutoff="$BASELINE_END" 'NR>1 && $2 <= cutoff' data/features.csv >> data/baseline.csv
BASELINE_ROWS=$(($(wc -l < data/baseline.csv) - 1))
echo "      baseline rows: $BASELINE_ROWS, total rows: $TOTAL_ROWS"

# Run detection.
export PATH="$HOME/.local/bin:$PATH"
.venv/bin/python detect/detect.py data/features.csv \
  --train data/baseline.csv --contamination 0.12 2>&1 | tee /tmp/detection_output.txt

# Labeled report: match scored rows to attack windows.
echo ""
echo "============================================================"
echo " Per-Attack-Type Detection Report"
echo "============================================================"
.venv/bin/python "$SCRIPT_DIR/report.py" data/features_scored.csv data/labels.csv "$TARGET"

echo ""
echo "Done. Artifacts:"
echo "  data/features.csv         — raw feature vectors"
echo "  data/baseline.csv         — baseline training data"
echo "  data/features_scored.csv  — scored with anomaly labels"
echo "  data/labels.csv           — attack schedule"
