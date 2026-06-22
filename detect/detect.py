#!/usr/bin/env python3
"""
Container anomaly detector — per-container IsolationForest + PCA.

Trains a SEPARATE model for each container name so the anomaly threshold is
calibrated to that container's own baseline. A busy container (napcat doing
33M syscalls/window) gets a different threshold than a quiet one (astrbot at
230). This is critical: a global model drowns attack signals in baseline noise.

Usage:
    python detect.py features.csv --train baseline.csv [--contamination 0.12]
"""
import argparse
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler


IDENTITY_COLS = ["window_start", "window_end", "container_id", "name", "image"]
# Security-sensitive syscalls: any activity here is suspicious if baseline is 0.
SENSITIVE = [
    "sys_priv_escalate", "sys_escape_attempt", "sys_file_unlink",
    "sys_file_rename", "sys_file_perm", "sys_proc_kill",
]


def engineer_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Build the model input: syscall ratios + log volumes + sensitive flags.

    Ratios normalize volume away (file_open/total instead of raw file_open).
    Log1p compresses orders-of-magnitude differences. Sensitive-syscall flags
    catch low-volume but high-signal activity (even 1 ptrace call is notable).
    """
    raw = df.drop(columns=IDENTITY_COLS, errors="ignore").fillna(0)
    X = raw.copy()

    sys_total = raw.get("sys_total", pd.Series(0, index=df.index))
    safe_total = sys_total.where(sys_total > 0, 1)
    sys_cols = [c for c in raw.columns if c.startswith("sys_") and c != "sys_total"]
    for c in sys_cols:
        X[f"{c}_ratio"] = raw[c] / safe_total

    total_bytes = (raw.get("tcp_bytes_tx", 0) + raw.get("tcp_bytes_rx", 0))
    total_bytes = total_bytes.where(total_bytes > 0, 1)
    if "tcp_bytes_tx" in raw:
        X["tcp_tx_ratio"] = raw["tcp_bytes_tx"] / total_bytes
    if "tcp_retrans" in raw and "tcp_bytes_tx" in raw:
        X["tcp_retrans_rate"] = raw["tcp_retrans"] / (raw["tcp_bytes_tx"] / 1e6 + 1)

    for c in ["tcp_bytes_tx", "tcp_bytes_rx", "cpu_runtime_ns", "sys_total"]:
        if c in raw.columns:
            X[f"{c}_log"] = np.log1p(raw[c].clip(lower=0))

    # Sensitive-syscall flags: binary "any activity?" per window.
    for c in SENSITIVE:
        if c in raw.columns:
            X[f"{c}_flag"] = (raw[c] > 0).astype(float)

    drop = set(sys_cols + ["tcp_bytes_tx", "tcp_bytes_rx", "cpu_runtime_ns"])
    keep = [c for c in X.columns if c not in drop]
    return X[keep], keep


def train_one_model(df_train_subset: pd.DataFrame, contamination):
    """Fit scaler + IsolationForest + PCA on one container's baseline."""
    X, feat = engineer_features(df_train_subset)
    if len(X) < 2:
        return None, feat
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    # n_estimators scaled to data size, clamped.
    n_est = max(50, min(300, len(X) * 20))
    iso = IsolationForest(n_estimators=n_est, contamination=contamination, random_state=42)
    iso.fit(Xs)
    pca = PCA(n_components=min(2, len(feat)))
    pca.fit(Xs)
    return {"scaler": scaler, "iso": iso, "pca": pca, "feat": feat}, feat


def score_one(model, df_subset: pd.DataFrame):
    """Score rows with a trained model. Returns DataFrame with score/anomaly."""
    X, feat = engineer_features(df_subset)
    for c in feat:
        if c not in X.columns:
            X[c] = 0.0
    X = X[feat]
    Xs = model["scaler"].transform(X)
    proj = model["pca"].transform(Xs)
    recon = np.linalg.norm(Xs - model["pca"].inverse_transform(proj), axis=1)
    return pd.DataFrame({
        "score": model["iso"].decision_function(Xs),
        "anomaly": model["iso"].predict(Xs),
        "recon_err": recon,
        "pca1": proj[:, 0],
        "pca2": proj[:, 1] if proj.shape[1] > 1 else 0.0,
    }, index=df_subset.index)


def fit_and_score(df_train: pd.DataFrame, df_score: pd.DataFrame, contamination):
    """Two-layer detection:

    Layer 1 (rule-based): any window with security-sensitive syscalls > 0
    (priv_escalate, escape_attempt, file_unlink, file_perm) that were ZERO in
    baseline → immediately flagged. These are unambiguous attack signals that
    don't need ML.

    Layer 2 (IsolationForest): behavioral anomaly detection for pattern
    deviations that rules don't catch (e.g., unusual syscall ratio mix, network
    direction imbalance). Per-container models for known containers; global
    model for unknowns (new/attack containers).
    """
    # --- Layer 1: rule-based sensitive syscall detection ---
    sensitive_cols = {
        "sys_priv_escalate": "priv_escalate baseline max",
        "sys_escape_attempt": "escape_attempt baseline max",
        "sys_file_unlink": "file_unlink baseline max",
        "sys_file_perm": "file_perm baseline max",
    }
    # Compute baseline maxima (what's "normal" for each sensitive syscall).
    baseline_max = {}
    for col in sensitive_cols:
        if col in df_train.columns:
            baseline_max[col] = df_train[col].max()

    rule_flags = pd.Series(False, index=df_score.index)
    rule_reasons = pd.Series("", index=df_score.index)
    for col in sensitive_cols:
        if col not in df_score.columns:
            continue
        threshold = baseline_max.get(col, 0)
        triggered = df_score[col] > threshold
        rule_flags = rule_flags | triggered
        rule_reasons[triggered] = rule_reasons[triggered] + f"{col.replace('sys_','')}>{int(threshold)} "

    # --- Layer 2: IsolationForest per-container + global fallback ---
    models = {}
    global_model, _ = train_one_model(df_train, contamination)
    models["__global__"] = global_model
    for name, grp in df_train.groupby(df_train["name"].fillna("host")):
        if len(grp) >= 3:
            m, _ = train_one_model(grp, contamination)
            if m is not None:
                models[name] = m

    results = []
    for name, grp in df_score.groupby(df_score["name"].fillna("host")):
        model = models.get(name, models.get("__global__"))
        if model is None:
            model = global_model
        scored = score_one(model, grp)
        for col in scored.columns:
            grp = grp.assign(**{col: scored[col]})
        results.append(grp)
    result = pd.concat(results).sort_index()

    # --- Merge layers: anomaly if EITHER layer fires ---
    result["rule_flag"] = rule_flags
    result["rule_reason"] = rule_reasons
    # Override: if rule fires, force anomaly regardless of ML score.
    result.loc[result["rule_flag"], "anomaly"] = -1
    result.loc[result["rule_flag"], "score"] = result.loc[result["rule_flag"], "score"].clip(upper=-0.01)
    return result


def report(result: pd.DataFrame, df_train: pd.DataFrame):
    print("\n" + "=" * 72)
    n_anom = (result["anomaly"] == -1).sum()
    print(f"Rows scored: {len(result)}  |  Anomalies: {n_anom}  "
          f"(per-container models for {result['name'].nunique()} entities)")
    print("=" * 72)

    for name, grp in result.groupby(result["name"].fillna("host")):
        n = (grp["anomaly"] == -1).sum()
        med = grp["score"].median()
        flag = " *** ANOMALOUS" if n > 0 else ""
        print(f"  {name:<30s} rows={len(grp):<3d} anomalies={n:<2d} "
              f"median_score={med:+.4f}{flag}")

    flagged = result[result["anomaly"] == -1].sort_values("score")
    if len(flagged):
        print("\n--- Flagged windows (most anomalous first, top 15) ---")
        for _, row in flagged.head(15).iterrows():
            name_val = row.get("name")
            label = str(name_val) if pd.notna(name_val) and name_val else "host"
            print(f"  [{row.get('window_end','?')}] {label:<24s} "
                  f"score={row['score']:+.4f} recon={row['recon_err']:.2f} | "
                  f"open={row.get('sys_file_open',0)} exec={row.get('sys_proc_exec',0)} "
                  f"priv={row.get('sys_priv_escalate',0)} esc={row.get('sys_escape_attempt',0)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("features", help="CSV to score")
    ap.add_argument("--train", help="baseline CSV to fit on")
    ap.add_argument("--contamination", default="auto")
    args = ap.parse_args()

    df = pd.read_csv(args.features)
    train_df = pd.read_csv(args.train) if args.train else df
    contam = args.contamination
    try:
        contam = float(contam)
    except ValueError:
        pass

    result = fit_and_score(train_df, df, contam)
    report(result, train_df)

    # PCA loadings for the global model (representative).
    X, feat = engineer_features(train_df)
    if len(X) >= 2:
        scaler = StandardScaler()
        pca = PCA(n_components=min(2, len(feat)))
        pca.fit(scaler.fit_transform(X))
        print("\n--- PCA loadings (global, top feature weights) ---")
        for i, comp in enumerate(pca.components_):
            top = np.argsort(np.abs(comp))[-5:][::-1]
            weights = ", ".join(f"{feat[j]}={comp[j]:+.2f}" for j in top)
            print(f"  PC{i+1}: {weights}")

    out_path = args.features.replace(".csv", "_scored.csv")
    result.to_csv(out_path, index=False)
    print(f"\nScored output: {out_path}")


if __name__ == "__main__":
    main()
