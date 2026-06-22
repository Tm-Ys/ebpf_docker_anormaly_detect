#!/usr/bin/env python3
"""
Labeled detection report: matches scored feature rows to the attack schedule
and computes per-attack-type detection rate.

For each attack window, checks whether the target container's feature vector
was flagged as anomalous by the IsolationForest.
"""
import sys
import pandas as pd
from datetime import datetime, timedelta


def parse_ts(s):
    """Parse a CSV timestamp like 2026-06-22T20:01:30 into datetime."""
    return datetime.strptime(s.strip(), "%Y-%m-%dT%H:%M:%S")


def main():
    scored_path = sys.argv[1]
    labels_path = sys.argv[2]
    target = sys.argv[3]

    scored = pd.read_csv(scored_path)
    labels = pd.read_csv(labels_path)

    # Filter to the target container's rows.
    scored["window_end_dt"] = scored["window_end"].apply(parse_ts)
    target_rows = scored[scored["name"] == target].copy()

    if len(target_rows) == 0:
        print(f"  ERROR: no rows for target '{target}' in scored data")
        sys.exit(1)

    print(f"  Target: {target}  ({len(target_rows)} windows)")
    print(f"  {'Attack':<22s} {'Windows':>7s} {'Detected':>9s} {'Rate':>6s}  Min Score")
    print("  " + "-" * 62)

    total_attacks = 0
    total_detected = 0

    for _, label in labels.iterrows():
        atk_type = label["attack_type"]
        start = parse_ts(label["start"])
        end = parse_ts(label["end"]) + timedelta(seconds=2)  # buffer

        # Find target windows that fall within this attack's time range.
        in_window = target_rows[
            (target_rows["window_end_dt"] >= start)
            & (target_rows["window_end_dt"] <= end)
        ]
        n_windows = len(in_window)
        if n_windows == 0:
            print(f"  {atk_type:<22s} {'0':>7s} {'-':>9s} {'-':>6s}  (no windows captured)")
            continue

        n_detected = int((in_window["anomaly"] == -1).sum())
        rate = n_detected / n_windows * 100
        min_score = in_window["score"].min()

        total_attacks += n_windows
        total_detected += n_detected

        flag = " ✓" if n_detected > 0 else " ✗"
        print(f"  {atk_type:<22s} {n_windows:>7d} {n_detected:>9d} {rate:>5.0f}%  {min_score:+.4f}{flag}")

    # Summary.
    print("  " + "-" * 62)
    if total_attacks > 0:
        overall = total_detected / total_attacks * 100
        print(f"  {'TOTAL':<22s} {total_attacks:>7d} {total_detected:>9d} {overall:>5.0f}%")

    # Baseline false-positive check: windows BEFORE the first attack.
    first_attack_start = parse_ts(labels.iloc[0]["start"])
    baseline = target_rows[target_rows["window_end_dt"] < first_attack_start]
    if len(baseline) > 0:
        fp = int((baseline["anomaly"] == -1).sum())
        fpr = fp / len(baseline) * 100
        print(f"\n  Baseline false positives: {fp}/{len(baseline)} ({fpr:.0f}%)")
        if fpr < 20:
            print("  FPR acceptable (<20%) ✓")
        else:
            print("  FPR high — may need more baseline data or tuning")


if __name__ == "__main__":
    main()
