#!/usr/bin/env python3
"""
Visualization with bilingual (English + Chinese) labels.

1. global_pca.png          — all containers in one PCA space (全局PCA散点)
2. pca_per_container.png   — single container's behavioral space (单容器PCA)
3. sensitive_syscalls.png  — attack syscall signatures (攻击签名)
4. score_heatmap.png       — feature intensity timeline (特征热力图)
"""
import sys, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.dates import DateFormatter
from matplotlib.patches import Ellipse
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from datetime import datetime

# --- CJK font setup ---
for fp in ["/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
           "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Light.ttc",
           "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Bold.ttc"]:
    if os.path.exists(fp):
        font_manager.fontManager.addfont(fp)
plt.rcParams["font.sans-serif"] = ["Noto Sans CJK SC", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

# Bilingual attack labels.
ATK_LABELS = {
    "baseline":          "Baseline (基线)",
    "01_recon_filescan": "File Recon (文件侦察)",
    "02_recon_sensitive":"Sensitive Read (敏感读取)",
    "03_net_scan":       "Net Scan (网络扫描)",
    "04_net_exfil":      "Data Exfil (数据外泄)",
    "05_crypto_mine":    "Crypto Mine (挖矿)",
    "06_reverse_shell":  "Rev Shell (反弹Shell)",
    "07_priv_esc":       "Priv Esc (提权)",
    "08_escape_probe":   "Escape (逃逸探测)",
}

SENSITIVE = ["sys_priv_escalate", "sys_escape_attempt", "sys_file_unlink",
             "sys_file_rename", "sys_file_perm", "sys_proc_kill"]
VOLUME    = ["sys_file_open", "sys_file_read", "sys_file_write",
             "sys_net_connect", "sys_net_send", "sys_proc_exec", "sys_proc_fork"]
SENSITIVE_SHORT = {"sys_priv_escalate": "priv_escal (提权)",
                   "sys_escape_attempt": "escape (逃逸)",
                   "sys_file_unlink": "unlink (删除)",
                   "sys_file_rename": "rename (重命名)",
                   "sys_file_perm": "perm (权限改)",
                   "sys_proc_kill": "kill (杀进程)"}
VOLUME_SHORT = {"sys_file_open": "open (打开)",
                "sys_file_read": "read (读)",
                "sys_file_write": "write (写)",
                "sys_net_connect": "connect (连接)",
                "sys_net_send": "send (发送)",
                "sys_proc_exec": "exec (执行)",
                "sys_proc_fork": "fork (派生)"}


def ts(s): return datetime.strptime(str(s).strip(), "%Y-%m-%dT%H:%M:%S")


def label_phases(df, labels, target):
    df = df.copy()
    df["phase"] = "baseline"
    if labels is not None:
        for _, l in labels.iterrows():
            s, e = ts(l["start"]), ts(l["end"])
            m = (df["name"].fillna("host") == target) & \
                (df["window_end"].apply(ts) >= s) & (df["window_end"].apply(ts) <= e)
            df.loc[m, "phase"] = l["attack_type"]
    return df


def plot_global_pca(df, labels, out):
    """Global PCA on ENGINEERED features (ratios + sensitive flags + log volumes).
    Raw counts give near-zero separation because volume noise dominates. The
    engineered features are what IsolationForest actually sees — using them
    here makes the scatter show the model's decision boundary."""
    # --- Feature engineering (same as detect.py) ---
    raw = df.drop(columns=[c for c in df.columns
                           if c in {"window_start","window_end","container_id","name",
                                    "image","score","anomaly","recon_err","pca1","pca2"}],
                  errors="ignore").fillna(0)
    raw = raw.select_dtypes(include=[np.number])
    X = raw.copy()
    st = raw.get("sys_total", pd.Series(0, index=df.index)); st = st.where(st > 0, 1)
    for c in raw.columns:
        if c.startswith("sys_") and c != "sys_total":
            X[f"{c}_ratio"] = raw[c] / st
    for c in ["tcp_bytes_tx", "tcp_bytes_rx", "cpu_runtime_ns", "sys_total"]:
        if c in raw:
            X[f"{c}_log"] = np.log1p(raw[c].clip(lower=0))
    for c in SENSITIVE:
        if c in raw:
            X[f"{c}_flag"] = (raw[c] > 0).astype(float)
    # Drop raw counts; keep ratios/flags/logs only.
    drop = [c for c in X.columns if c.startswith("sys_") and c not in
            [f"{s}_ratio" for s in ["sys_total"]] and
            not c.endswith(("_ratio", "_flag", "_log"))]
    drop += [c for c in ["tcp_bytes_tx","tcp_bytes_rx","cpu_runtime_ns"] if c in X]
    X = X[[c for c in X.columns if c not in drop]]

    Xs = StandardScaler().fit_transform(X.values)
    P = PCA(2).fit_transform(Xs)

    known = {"nginx", "redis"}
    df = df.copy()
    cat = []
    for _, r in df.iterrows():
        name = str(r.get("name", "") or "")
        if name in known:
            cat.append("baseline")
        elif name in ("host", "nan", ""):
            cat.append("host")
        else:
            cat.append("attack")
    df["cat"] = cat

    def lookup(row):
        if row["cat"] != "attack":
            return row["cat"]
        t = ts(row["window_end"])
        for _, l in labels.iterrows():
            if ts(l["start"]) <= t <= ts(l["end"]):
                return l["attack_type"]
        return "attack_other"
    df["label"] = df.apply(lookup, axis=1)

    fig, ax = plt.subplots(figsize=(13, 8))
    # Baselines + host.
    for c, col, mk in [("baseline", "steelblue", "o"), ("host", "silver", "x")]:
        mask = (df["cat"] == c).values
        if mask.any():
            lbl = "Baseline / nginx+redis (基线)" if c == "baseline" else "Host (宿主机)"
            ax.scatter(P[mask, 0], P[mask, 1], color=col,
                       s=70 if c == "baseline" else 40,
                       alpha=0.5, marker=mk,
                       edgecolors="white" if c == "baseline" else None,
                       linewidths=0.5, label=lbl, zorder=2)

    # Baseline confidence ellipse.
    base_pts = P[(df["cat"] == "baseline").values]
    if len(base_pts) >= 3:
        mean = base_pts.mean(axis=0)
        cov = np.cov(base_pts.T) + np.eye(2) * 0.01
        eigval, eigvec = np.linalg.eigh(cov)
        angle = np.degrees(np.arctan2(eigvec[1, 1], eigvec[0, 1]))
        w, h = 2 * np.sqrt(np.maximum(eigval, 0.01)) * 2.5
        ell = Ellipse(xy=mean, width=w, height=h, angle=angle,
                      fill=True, facecolor="steelblue", alpha=0.1,
                      edgecolor="navy", linewidth=2, linestyle="--",
                      label="Baseline 2.5σ (基线置信域)")
        ax.add_patch(ell)

    # Attacks colored by type.
    atk_types = sorted(df[df["cat"] == "attack"]["label"].unique())
    cmap = plt.cm.Set1
    for i, atk in enumerate(atk_types):
        mask = (df["label"] == atk).values
        if mask.any():
            display = ATK_LABELS.get(atk, atk)
            ax.scatter(P[mask, 0], P[mask, 1], color=cmap(i % 9), s=120, alpha=0.8,
                       marker="^", edgecolors="darkred", linewidths=0.8,
                       label=display, zorder=5)

    ax.set_xlabel("PC1 — Sensitive Syscall Activity (安全敏感活动)", fontsize=12)
    ax.set_ylabel("PC2 — Behavioral Pattern (行为模式)", fontsize=12)
    ax.set_title("Global PCA: Baselines vs Attack Containers\n"
                 "全局PCA: 基线 vs 攻击 — 三角离蓝团越远 = 异常越显著", fontsize=13)
    ax.legend(fontsize=8, loc="best", framealpha=0.9, ncol=2)
    ax.grid(True, alpha=0.2)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  saved {out}")


def plot_pca_per_container(df, target, out):
    sub = df[df["name"].fillna("host") == target].copy()
    if len(sub) < 4:
        print(f"  skip PCA per-container: only {len(sub)} rows for {target}")
        return
    feat = [c for c in sub.columns
            if pd.api.types.is_numeric_dtype(sub[c])
            and c not in {"score", "anomaly", "recon_err", "pca1", "pca2"}]
    X = StandardScaler().fit_transform(sub[feat].fillna(0).values)
    pca = PCA(2)
    P = pca.fit_transform(X)

    fig, ax = plt.subplots(figsize=(9, 7))
    cmap = plt.cm.Set1
    phases = sorted(sub["phase"].unique())
    for i, phase in enumerate(phases):
        mask = (sub["phase"] == phase).values
        is_base = phase == "baseline"
        display = ATK_LABELS.get(phase, phase)
        ax.scatter(P[mask, 0], P[mask, 1],
                   color="black" if is_base else cmap(i % 9),
                   s=150 if is_base else 100,
                   marker="o" if is_base else "^",
                   edgecolors="white", linewidths=0.8,
                   alpha=0.85 if is_base else 0.75,
                   label=f"{display} (n={mask.sum()})",
                   zorder=5 if is_base else 3)

    # Baseline confidence ellipse.
    base_pts = P[(sub["phase"] == "baseline").values]
    if len(base_pts) >= 3:
        mean = base_pts.mean(axis=0)
        cov = np.cov(base_pts.T) + np.eye(2) * 0.01
        eigval, eigvec = np.linalg.eigh(cov)
        angle = np.degrees(np.arctan2(eigvec[1, 1], eigvec[0, 1]))
        w, h = 2 * np.sqrt(np.maximum(eigval, 0.01)) * 2.5
        ell = Ellipse(xy=mean, width=w, height=h, angle=angle,
                      fill=False, edgecolor="black", linewidth=2, linestyle="--",
                      alpha=0.5, label="Baseline 2.5σ (基线置信域)")
        ax.add_patch(ell)

    ax.set_xlabel(f"PC1 ({pca.explained_variance_ratio_[0]:.0%})", fontsize=12)
    ax.set_ylabel(f"PC2 ({pca.explained_variance_ratio_[1]:.0%})", fontsize=12)
    ax.set_title(f"{target}: PCA Behavioral Space\n"
                 f"{target} 的PCA行为空间 — 基线 vs 攻击偏离", fontsize=12)
    ax.legend(fontsize=8, loc="best", framealpha=0.9)
    ax.grid(True, alpha=0.2)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  saved {out}")


def plot_sensitive_syscalls(df, target, out):
    sub = df[df["name"].fillna("host") == target]
    phases = sorted(sub["phase"].unique())

    fig, axes = plt.subplots(1, 2, figsize=(18, 7))
    x = np.arange(len(phases))
    width = 0.13

    # Left: sensitive.
    ax = axes[0]
    for i, col in enumerate(SENSITIVE):
        if col not in sub.columns:
            continue
        vals = [sub[sub["phase"] == p][col].sum() for p in phases]
        logvals = [np.log1p(v) for v in vals]
        ax.bar(x + i * width, logvals, width, label=SENSITIVE_SHORT.get(col, col))
        for xi, (lv, v) in enumerate(zip(logvals, vals)):
            if v > 0 and lv > 0.5:
                txt = f"{v:.0f}" if v < 1000 else f"{v/1e3:.0f}K" if v < 1e6 else f"{v/1e6:.1f}M"
                ax.annotate(txt, (xi + i * width, lv), fontsize=6, ha="center", va="bottom")
    ax.set_xticks(x + width * 2.5)
    ax.set_xticklabels([ATK_LABELS.get(p, p).split("(")[0].strip() for p in phases],
                       fontsize=7, rotation=35, ha="right")
    ax.set_ylabel("log(1 + count)  对数计数", fontsize=10)
    ax.set_title("Security-Critical Syscalls\n安全敏感系统调用 (提权/逃逸/删除)", fontsize=11)
    ax.legend(fontsize=7)
    ax.grid(True, alpha=0.2, axis="y")

    # Right: volume.
    ax = axes[1]
    for i, col in enumerate(VOLUME):
        if col not in sub.columns:
            continue
        vals = [sub[sub["phase"] == p][col].sum() for p in phases]
        logvals = [np.log1p(v) for v in vals]
        ax.bar(x + i * width, logvals, width, label=VOLUME_SHORT.get(col, col))
    ax.set_xticks(x + width * 3)
    ax.set_xticklabels([ATK_LABELS.get(p, p).split("(")[0].strip() for p in phases],
                       fontsize=7, rotation=35, ha="right")
    ax.set_ylabel("log(1 + count)  对数计数", fontsize=10)
    ax.set_title("Behavioral Syscalls\n行为系统调用 (文件/网络/进程)", fontsize=11)
    ax.legend(fontsize=7, loc="upper right")
    ax.grid(True, alpha=0.2, axis="y")

    fig.suptitle(f"Attack Signatures on {target} — Absolute Syscall Counts\n"
                 f"攻击签名 — 各攻击类型的系统调用绝对计数 (对数刻度)", fontsize=13, y=1.02)
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  saved {out}")


def plot_score_heatmap(df, target, out):
    sub = df[df["name"].fillna("host") == target].sort_values("window_end").copy()
    if len(sub) < 4:
        print(f"  skip heatmap: only {len(sub)} rows")
        return
    cols = VOLUME + SENSITIVE + ["tcp_bytes_tx", "tcp_bytes_rx", "cpu_runtime_ns"]
    cols = [c for c in cols if c in sub.columns]
    M = sub[cols].fillna(0).values.T.astype(float)
    Mlog = np.log1p(M)
    rowmax = Mlog.max(axis=1, keepdims=True)
    rowmax[rowmax == 0] = 1
    Mn = Mlog / rowmax

    fig, ax = plt.subplots(figsize=(16, 8))
    im = ax.imshow(Mn, aspect="auto", cmap="YlOrRd", interpolation="nearest")
    labels_y = [c.replace("sys_", "").replace("tcp_", "").replace("cpu_", "").replace("_", " ")
                for c in cols]
    ax.set_yticks(range(len(cols)))
    ax.set_yticklabels(labels_y, fontsize=8)
    ax.set_xticks(range(len(sub)))
    ax.set_xticklabels([str(t)[-8:] for t in sub["window_end"].values],
                       fontsize=6, rotation=45, ha="right")

    # Color x labels by phase.
    phase_colors = {"baseline": "gray"}
    cmap = plt.cm.Set1
    for i, p in enumerate(sorted(sub["phase"].unique())):
        if p != "baseline":
            phase_colors[p] = cmap(i % 9)
    for i, p in enumerate(sub["phase"].values):
        ax.get_xticklabels()[i].set_color(phase_colors.get(p, "black"))

    prev = None
    for i, p in enumerate(sub["phase"].values):
        if p != prev and i > 0:
            ax.axvline(i - 0.5, color="blue", linewidth=0.8, alpha=0.4)
        prev = p

    ax.set_title(f"{target}: Feature Intensity Heatmap\n"
                 f"特征强度热力图 — 每列=10秒窗口, 颜色越红=活动越强\n"
                 f"(蓝线=攻击阶段分界)", fontsize=12)
    plt.colorbar(im, ax=ax, label="Normalized Intensity (归一化强度)", fraction=0.02)
    fig.tight_layout()
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f"  saved {out}")


def main():
    scored = sys.argv[1] if len(sys.argv) > 1 else "data/features_scored.csv"
    labels = sys.argv[2] if len(sys.argv) > 2 else "data/labels.csv"
    target = sys.argv[3] if len(sys.argv) > 3 else "nginx"
    out_dir = os.path.join(os.path.dirname(scored), "plots")
    os.makedirs(out_dir, exist_ok=True)

    df = pd.read_csv(scored)
    lbl = pd.read_csv(labels) if os.path.exists(labels) else None
    df = label_phases(df, lbl, target)
    print(f"target={target}  rows={len(df)}  attacks={len(lbl) if lbl is not None else 0}")

    print("generating:")
    plot_global_pca(df, lbl, os.path.join(out_dir, "global_pca.png"))
    plot_pca_per_container(df, target, os.path.join(out_dir, "pca_per_container.png"))
    plot_sensitive_syscalls(df, target, os.path.join(out_dir, "sensitive_syscalls.png"))
    plot_score_heatmap(df, target, os.path.join(out_dir, "score_heatmap.png"))
    print(f"done → {out_dir}/")


if __name__ == "__main__":
    main()
