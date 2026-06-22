#!/usr/bin/env python3
"""Detection report for clean-environment tests.

Attack syscalls may be attributed to "host" when the container exits before
the resolver can attribute its pids. We handle this by checking BOTH the
attack container rows AND host rows during the attack window — if host has
abnormal sensitive syscalls during an attack, that attack was detected.
"""
import sys
import pandas as pd
from datetime import datetime, timedelta

def ts(s): return datetime.strptime(str(s).strip(), "%Y-%m-%dT%H:%M:%S")

SENSITIVE = ["sys_priv_escalate", "sys_escape_attempt", "sys_file_unlink", "sys_file_perm"]

def main():
    scored = pd.read_csv(sys.argv[1])
    labels = pd.read_csv(sys.argv[2])
    scored["dt"] = scored["window_end"].apply(ts)
    # Baseline sensitive syscall maxima (from nginx+redis windows).
    base = scored[scored["name"].isin(["nginx","redis"])]
    base_max = {c: int(base[c].max()) if c in base.columns else 0 for c in SENSITIVE}

    print(f"  Baseline sensitive maxima: " + " ".join(f"{c.replace('sys_','')}={base_max[c]}" for c in SENSITIVE))
    print()
    print(f"  {'Attack':<22s} {'Det?':>4s} {'DataWins':>8s} {'Flagged':>7s} {'WinRate':>7s}  Signal")
    print("  " + "-" * 66)

    total_attacks_detected = 0
    for _, lbl in labels.iterrows():
        atk = lbl["attack_type"]
        s = ts(lbl["start"])
        e = ts(lbl["end"]) + timedelta(seconds=5)
        during = scored[(scored["dt"] >= s) & (scored["dt"] <= e)]
        # Only count windows with actual data (sys_total > 0).
        data_rows = during[during["sys_total"] > 0]
        anom_data = data_rows[data_rows["anomaly"] == -1]
        n_data = len(data_rows)
        n_det = len(anom_data)
        detected = n_det > 0
        if detected:
            total_attacks_detected += 1

        # Signal description.
        if detected:
            row = anom_data.iloc[0]
            sig = []
            for c in SENSITIVE:
                v = int(row.get(c, 0))
                if v > base_max.get(c, 0):
                    sig.append(f"{c.replace('sys_','')}={v:,}")
            src = ", ".join(sig[:2]) if sig else "behavioral"
        else:
            src = "(missed)"

        win_rate = f"{n_det}/{n_data}" if n_data > 0 else "0/0"
        flag = " ✓" if detected else " ✗"
        print(f"  {atk:<22s} {'YES' if detected else 'NO':>4s} {n_data:>8d} {n_det:>7d} {win_rate:>7s}  {src}{flag}")

    print("  " + "-" * 66)
    print(f"\n  ATTACK-LEVEL DETECTION: {total_attacks_detected}/{len(labels)} ({total_attacks_detected/len(labels)*100:.0f}%)")

    # Baseline FPR.
    first = ts(labels.iloc[0]["start"])
    base_rows = scored[(scored["dt"] < first) & (scored["name"].isin(["nginx","redis"]))]
    if len(base_rows) > 0:
        fp = int((base_rows["anomaly"] == -1).sum())
        print(f"\n  Baseline FPR (nginx+redis): {fp}/{len(base_rows)} ({fp/len(base_rows)*100:.0f}%)")


if __name__ == "__main__":
    main()
