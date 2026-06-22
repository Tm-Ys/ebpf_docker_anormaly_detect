#!/usr/bin/env python3
"""
Detection report for dedicated-container tests. Each attack ran in its own
container, so we check whether that container's windows were flagged.
"""
import sys
import pandas as pd
from datetime import datetime, timedelta


def ts(s):
    return datetime.strptime(str(s).strip(), "%Y-%m-%dT%H:%M:%S")


def main():
    scored = pd.read_csv(sys.argv[1])
    labels = pd.read_csv(sys.argv[2])
    scored["dt"] = scored["window_end"].apply(ts)

    print(f"  {'Attack':<22s} {'Container':<28s} {'Wins':>4s} {'Det':>4s} {'Rate':>5s}  Min Score")
    print("  " + "-" * 70)

    total_w, total_d = 0, 0
    for _, lbl in labels.iterrows():
        cname = lbl["container_name"]
        atk = lbl["attack_type"]
        start = ts(lbl["start"])
        end = ts(lbl["end"]) + timedelta(seconds=8)

        # Find rows for this container within the attack window.
        # The container name in features may be the cid, not the docker name.
        # Match by time window instead — any non-baseline container active then.
        mask = (scored["dt"] >= start) & (scored["dt"] <= end) & \
               (scored["name"].fillna("") != "napcat") & \
               (scored["name"].fillna("") != "astrbot_p64p-astrbot_p64P-1") & \
               (scored["name"].fillna("host") != "host")
        in_win = scored[mask]

        if len(in_win) == 0:
            # Fall back: any anomalous non-baseline container in window
            in_win = scored[(scored["dt"] >= start) & (scored["dt"] <= end) &
                            (scored["name"].fillna("host") != "host") &
                            (scored["name"].fillna("") != "napcat")]
        n = len(in_win)
        d = int((in_win["anomaly"] == -1).sum()) if n > 0 else 0
        rate = f"{d/n*100:.0f}%" if n > 0 else "-"
        mscore = f"{in_win['score'].min():+.4f}" if n > 0 else "n/a"
        flag = " ✓" if d > 0 else " ✗"
        print(f"  {atk:<22s} {cname:<28s} {n:>4d} {d:>4d} {rate:>5s}  {mscore}{flag}")
        total_w += n
        total_d += d

    print("  " + "-" * 70)
    rate = f"{total_d/total_w*100:.0f}%" if total_w > 0 else "-"
    print(f"  {'TOTAL':<22s} {'':28s} {total_w:>4d} {total_d:>4d} {rate:>5s}")

    # Baseline FPR
    first_atk = ts(labels.iloc[0]["start"])
    baseline = scored[(scored["dt"] < first_atk) &
                      (scored["name"].fillna("host") != "host")]
    if len(baseline) > 0:
        fp = int((baseline["anomaly"] == -1).sum())
        print(f"\n  Baseline false positives: {fp}/{len(baseline)} ({fp/len(baseline)*100:.0f}%)")


if __name__ == "__main__":
    main()
