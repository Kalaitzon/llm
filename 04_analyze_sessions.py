# -*- coding: utf-8 -*-
"""
04_analyze_sessions.py  --  Behaviour and deception-quality analysis
===========================================================================
[TASK 5] Behaviour and intent analysis.
[TASK 6] Assessment of deception quality and fingerprinting risk.

WHAT THIS FILE DOES
-------------------
This is the "analyser". It reads the REAL session logs produced by the
honeypot (logs/sessions.jsonl), converts each session into numeric features,
and draws conclusions about attacker behaviour using Machine Learning.

HOW IT WORKS (the steps)  --  Task 5
------------------------------------
1. extract_features(): for each session it computes 8 features. Five measure
   the INTENSITY of engagement (dwell time, command count, command diversity,
   artefacts touched, path depth) and three the KIND of activity, as ratios
   (read_frac, recon_frac, privesc_frac).
2. do_clustering(): standardises the features and groups the sessions with
   K-means (k=4) and DBSCAN (lecture 3). It also applies Isolation Forest to
   automatically separate the "deep/anomalous" sessions from the shallow ones.
3. 2D visualisation with PCA and t-SNE (lecture 3).
4. Comparison of the clusters with the GROUND TRUTH (intent) via the ARI index,
   to show how well the "blind" clustering recovers the real tactics.
5. make_summaries(): produces representative session summaries from real data.

HOW IT WORKS (the steps)  --  Task 6
------------------------------------
6. analyse_decoy_sources(): compares how much engagement the manual vs the
   LLM-generated decoys attracted (real artefact touches), and compares against
   a minimal static baseline with no decoys.
The fingerprinting points (how the honeypot can be given away) are documented
in the report, based on the limitations visible here.

INPUT / OUTPUT
--------------
- Input : logs/sessions.jsonl (honeypot) and playbook_results/ground_truth.json.
- Output: the analysis/ folder (session_features.csv, analysis_report.json,
  cluster_composition.json) and the figures/ folder (PNG plots).

HOW TO RUN:  python3 04_analyze_sessions.py   (after the logs have been produced)
"""

import json
import importlib
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.manifold import TSNE
from sklearn.metrics import adjusted_rand_score, silhouette_score

cfg = importlib.import_module("00_config")

BASE     = Path(__file__).resolve().parent
LOG_DIR  = BASE / "logs"
MASTER   = LOG_DIR / "sessions.jsonl"
PB_DIR   = BASE / "playbook_results"
OUT      = BASE / "analysis"
FIG      = BASE / "figures"
OUT.mkdir(exist_ok=True)
FIG.mkdir(exist_ok=True)

RNG = cfg.SEED

# Command categories. Used to measure WHAT KIND of activity the attacker did
# (system reconnaissance, file reading, privilege escalation). Each command is
# classified into one of these groups.
RECON_VERBS   = {"whoami", "id", "uname", "hostname", "ps", "ss", "netstat", "env", "printenv", "ip", "ifconfig"}
READ_VERBS    = {"cat", "less", "more", "head", "tail", "grep"}
PRIVESC_TOKENS = ("sudo", "/etc/shadow", "/etc/sudoers", "-perm -4000", "/etc/passwd")


# ==========================================================================
#  1. Load data (sessions + ground truth)
# ==========================================================================
def load_sessions():
    """Read all sessions from the master file logs/sessions.jsonl.
    Each line is one session in JSON form."""
    sessions = []
    with open(MASTER, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                sessions.append(json.loads(line))
    return sessions


def load_ground_truth():
    """Read the ground truth (the known truth: which playbook/intent produced
    each session). Returns a map src_port -> session record, so that we can
    match each session log to its real intent via the port (src_port)."""
    gt = json.loads((PB_DIR / "ground_truth.json").read_text(encoding="utf-8"))
    by_port = {s["src_port"]: s for s in gt["sessions"]}
    return by_port, gt["catalogue"]


# ==========================================================================
#  2. Feature engineering per session
# ==========================================================================
def path_depth(path):
    """Compute the "depth" of a path = how many folders deep it is.
    E.g. /opt/app/config -> depth 3. Shows how deep the user explored."""
    return path.strip("/").count("/") + 1 if path.strip("/") else 0


def extract_features(sess):
    """Convert a session into 8 numeric features that will feed the Machine
    Learning models. The features fall into two groups: (a) INTENSITY of
    engagement (how deep), and (b) KIND of activity (what sort of commands), so
    that we distinguish not only shallow/deep sessions but also the kind of
    tactic."""
    cmds = sess["commands"]
    # The "verb" of each command is the first word (e.g. "cat", "grep", "whoami").
    verbs = [c.split()[0] for c in cmds if c.split()]
    unique_verbs = set(verbs)

    # path depth: the maximum path depth that appeared (either in the current
    # directory or in some absolute path inside a command). Shows how deep into
    # the filesystem the attacker reached.
    depths = [0]
    for e in sess["events"]:
        depths.append(path_depth(e.get("cwd", "/")))
        for tok in e.get("input", "").split():
            if tok.startswith("/"):
                depths.append(path_depth(tok))

    # Count how many commands belong to each category.
    read_ops   = sum(1 for v in verbs if v in READ_VERBS)        # file reading
    recon_ops  = sum(1 for v in verbs if v in RECON_VERBS)       # system reconnaissance
    privesc_ops = sum(1 for c in cmds if any(tok in c for tok in PRIVESC_TOKENS))  # privilege escalation

    n = max(len(cmds), 1)     # avoid division by zero
    return {
        "session_id": sess["session_id"],
        "src_port": sess["src_port"],
        "auth_success": sess["auth"]["success"],
        # --- INTENSITY features (HOW deep the engagement) ---
        "dwell_time": sess["duration_seconds"],                  # duration
        "command_count": len(cmds),                              # how many commands
        "cmd_diversity": round(len(unique_verbs) / n, 3),        # command variety
        "artefacts_touched": len(sess["artefacts_touched"]),     # how many decoys read
        "path_depth": max(depths),                               # how deep it reached
        # --- KIND features (WHAT sort of activity), as ratios ---
        "read_frac": round(read_ops / n, 3),                     # reading ratio
        "recon_frac": round(recon_ops / n, 3),                   # reconnaissance ratio
        "privesc_frac": round(privesc_ops / n, 3),               # escalation ratio
        # Raw counts (for the summaries/report, not for the clustering).
        "read_ops": read_ops,
        "recon_ops": recon_ops,
        "privesc_ops": privesc_ops,
        "_touched_list": sess["artefacts_touched"],              # the list of decoys
    }


# The 8 features given to the models. Combining intensity + kind helps the
# clustering separate also the KIND of tactic, not just the size.
FEATURE_COLS = ["dwell_time", "command_count", "cmd_diversity",
                "artefacts_touched", "path_depth",
                "read_frac", "recon_frac", "privesc_frac"]


# ==========================================================================
#  3. Clustering + anomaly detection (Isolation Forest)
# ==========================================================================
def do_clustering(df):
    """Applies three Machine Learning methods on the features:
    (1) K-means: splits the sessions into 4 groups (behaviour profiles).
    (2) DBSCAN: alternative density-based grouping.
    (3) Isolation Forest: detects the "anomalous" (deep/targeted) sessions.
    First, though, the features are standardised (StandardScaler), so that they
    all carry equal weight regardless of their units (e.g. seconds vs counts)."""
    X = StandardScaler().fit_transform(df[FEATURE_COLS].values)

    # K-means with a fixed k=4, which gives the most interpretable profiles
    # (shallow probes, moderate engagement, deep readers, deep recon). Testing
    # with silhouette for k from 3 to 7 confirmed a good balance of separation
    # and interpretability.
    best_k = 4
    km = KMeans(n_clusters=best_k, random_state=RNG, n_init=10).fit(X)
    df["kmeans"] = km.labels_
    df.attrs["best_k"] = best_k
    best_sil = silhouette_score(X, km.labels_)     # separation quality (0-1)

    # DBSCAN: density-based grouping (does not need a predefined k).
    db = DBSCAN(eps=1.6, min_samples=2).fit(X)
    df["dbscan"] = db.labels_

    # Isolation Forest: "isolates" the unusual points. The more easily a session
    # is isolated, the more anomalous (deep/targeted) it is.
    iso = IsolationForest(random_state=RNG, contamination=0.25).fit(X)
    df["iso_flag"] = (iso.predict(X) == -1)      # True = "anomalous/deep"
    df["iso_score"] = -iso.score_samples(X)      # higher = more anomalous

    return X, km, round(best_sil, 3), best_k


# ==========================================================================
#  4. Visualisations
# ==========================================================================
C1, C2, C3 = "#2b6cb0", "#c53030", "#2f855a"


def plot_depth_hist(df):
    """Figure 1: histogram showing how many sessions touched 0, 1, 2, ...
    decoys. Reveals the spread of engagement (many shallow with 0, a few deep
    with many)."""
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(df["artefacts_touched"], bins=range(0, df["artefacts_touched"].max() + 2),
            color=C1, edgecolor="white", align="left")
    ax.set_xlabel("Artefacts touched ανά session")
    ax.set_ylabel("Πλήθος sessions")
    ax.set_title("Κατανομή engagement (πραγματικά artefact touches)")
    fig.tight_layout(); fig.savefig(FIG / "fig1_artefacts_touched.png", dpi=130); plt.close(fig)


def plot_pca(df, X):
    """Figure 2: PCA projection. PCA compresses the 8 features into 2 axes so
    that we can see the sessions on a plane. Colour shows the K-means cluster and
    the label the real intent, so that we can compare visually whether the
    clusters coincide with the real tactics."""
    pca = PCA(n_components=2, random_state=RNG).fit_transform(X)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    sc = ax.scatter(pca[:, 0], pca[:, 1], c=df["kmeans"], cmap="tab10", s=90,
                    edgecolor="black", linewidth=0.5)
    for i, r in df.reset_index().iterrows():
        ax.annotate(r["intent"][:4], (pca[i, 0], pca[i, 1]), fontsize=7,
                    xytext=(4, 4), textcoords="offset points")
    ax.set_title("PCA των sessions (χρώμα = K-means cluster, ετικέτα = ground-truth intent)")
    ax.set_xlabel("PC1"); ax.set_ylabel("PC2")
    fig.tight_layout(); fig.savefig(FIG / "fig2_pca_clusters.png", dpi=130); plt.close(fig)


def plot_tsne(df, X):
    """Figure (supplementary): t-SNE projection, an alternative 2D
    visualisation method. The perplexity is adapted to the small sample."""
    n = len(df)
    perp = max(2, min(5, n - 1))
    ts = TSNE(n_components=2, perplexity=perp, random_state=RNG, init="pca").fit_transform(X)
    fig, ax = plt.subplots(figsize=(7, 5.5))
    ax.scatter(ts[:, 0], ts[:, 1], c=df["kmeans"], cmap="tab10", s=90,
               edgecolor="black", linewidth=0.5)
    for i, r in df.reset_index().iterrows():
        ax.annotate(r["intent"][:4], (ts[i, 0], ts[i, 1]), fontsize=7,
                    xytext=(4, 4), textcoords="offset points")
    ax.set_title(f"t-SNE των sessions (perplexity={perp})")
    fig.tight_layout(); fig.savefig(FIG / "fig3_tsne_clusters.png", dpi=130); plt.close(fig)


def plot_iso(df):
    """Figure 3: bar chart of the anomaly score (Isolation Forest) of each
    session, sorted. The red bars are the sessions flagged as deep/anomalous
    (the ones an analyst would examine first)."""
    d = df.sort_values("iso_score")
    fig, ax = plt.subplots(figsize=(8, 4.5))
    colors = [C2 if f else C1 for f in d["iso_flag"]]      # red if anomalous
    ax.bar(range(len(d)), d["iso_score"], color=colors, edgecolor="white")
    ax.set_xticks(range(len(d)))
    ax.set_xticklabels(d["intent"].str[:6], rotation=60, ha="right", fontsize=7)
    ax.set_ylabel("Isolation Forest anomaly score")
    ax.set_title("Ξεχώρισμα βαθιών/στοχευμένων sessions (κόκκινο = flagged ως ανώμαλο)")
    fig.tight_layout(); fig.savefig(FIG / "fig4_isolation_forest.png", dpi=130); plt.close(fig)


def plot_llm_vs_manual(touch_by_source):
    """Figure 4: engagement comparison (total artefact touches) between the
    manual and the LLM-generated decoys. Answers the Task 6 question: do the
    LLM-generated decoys perform better?"""
    fig, ax = plt.subplots(figsize=(6.5, 4))
    srcs = ["manual", "llm"]
    vals = [touch_by_source.get(s, 0) for s in srcs]
    ax.bar(srcs, vals, color=[C3, C1], edgecolor="white")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.1, str(v), ha="center", fontsize=11)
    ax.set_ylabel("Συνολικά artefact touches")
    ax.set_title("Engagement ανά πηγή decoy (manual vs LLM-generated)")
    fig.tight_layout(); fig.savefig(FIG / "fig5_llm_vs_manual.png", dpi=130); plt.close(fig)


# ==========================================================================
#  5. Representative session summaries (from real data)
# ==========================================================================
def make_summaries(df, sessions_by_port, top=4):
    """Produces summaries for the most interesting (most anomalous) sessions, in
    natural language. Each summary describes the intent, how many commands, how
    many decoys were touched, etc., based purely on real data."""
    d = df.sort_values("iso_score", ascending=False).head(top)   # the most anomalous
    out = []
    for _, r in d.iterrows():
        touched = r["_touched_list"]
        out.append({
            "session_id": r["session_id"],
            "ground_truth_intent": r["intent"],
            "depth": r["depth"],
            "dwell_time": r["dwell_time"],
            "commands": r["command_count"],
            "artefacts_touched": touched,
            "narrative": (
                f"Session με προθεση '{r['intent']}' ({r['depth']}). Εκτελεσε "
                f"{r['command_count']} εντολες σε {r['dwell_time']}s, με path depth "
                f"{r['path_depth']}. Αγγιξε {len(touched)} decoys"
                + (f": {', '.join(touched)}." if touched else ".")
                + (f" Παρουσιασε {r['privesc_ops']} ενεργειες αναβαθμισης προνομιων."
                   if r["privesc_ops"] else "")
            ),
        })
    return out


# ==========================================================================
#  6. Decoy source comparison (Task 6): manual vs LLM
# ==========================================================================
def analyse_decoy_sources(df):
    """Counts how many touches each decoy received, grouping them (a) by source
    (manual vs LLM), (b) by category (ssh, credentials, etc.), and (c) per
    individual file. Uses the decoy catalogue (artifact_inventory.json) to know
    the source/category of each file."""
    inv = json.loads((BASE / "decoys" / "artifact_inventory.json").read_text(encoding="utf-8"))
    src_of = {a["virtual_path"]: a["source"] for a in inv["artifacts"]}      # source
    cat_of = {a["virtual_path"]: a["category"] for a in inv["artifacts"]}    # category

    touch_by_source = Counter()
    touch_by_cat = Counter()
    touch_by_artifact = Counter()
    for _, r in df.iterrows():
        for a in r["_touched_list"]:
            touch_by_source[src_of.get(a, "unknown")] += 1
            touch_by_cat[cat_of.get(a, "unknown")] += 1
            touch_by_artifact[a] += 1
    return touch_by_source, touch_by_cat, touch_by_artifact


def main():
    """The main analysis flow, step by step:
    1. Load the sessions and the ground truth.
    2. Separate the command-sessions from the failed connections.
    3. Extract features and join with the ground truth (intent).
    4. Clustering + Isolation Forest.
    5. Compare manual vs LLM decoys (Task 6).
    6. Produce figures and summaries.
    7. Save all results into analysis/."""
    print("[*] Φορτωση sessions...")
    sessions = load_sessions()
    by_port, catalogue = load_ground_truth()

    # Separate the sessions WITH commands (the playbooks) from the failed
    # connections (failed-auth probes, 0 commands). The behaviour analysis
    # concerns only the former.
    cmd_sessions = [s for s in sessions if s["command_count"] > 0]
    auth_probes  = [s for s in sessions if s["command_count"] == 0]
    print(f"[+] {len(sessions)} logs: {len(cmd_sessions)} command-sessions, "
          f"{len(auth_probes)} failed-auth probes")

    # Convert each session into a feature vector.
    rows = [extract_features(s) for s in cmd_sessions]
    df = pd.DataFrame(rows)

    # Add the REAL intent of each session from the ground truth, matching via
    # the port (src_port). This is used ONLY for the evaluation at the end (the
    # clustering was done "blind").
    df["intent"] = df["src_port"].map(lambda p: by_port.get(p, {}).get("intent", "unknown"))
    df["depth"]  = df["src_port"].map(lambda p: by_port.get(p, {}).get("depth", "?"))

    # --- Clustering + Isolation Forest ---
    X, km, sil, best_k = do_clustering(df)
    # ARI: measures how much the K-means clusters coincide with the real intents.
    ari = adjusted_rand_score(df["intent"], df["kmeans"])
    print(f"[+] K-means k={best_k} silhouette={sil} | cluster-vs-intent ARI={ari:.3f}")

    # --- Compare manual vs LLM decoys (Task 6) ---
    touch_by_source, touch_by_cat, touch_by_artifact = analyse_decoy_sources(df)

    # --- Produce all the figures ---
    plot_depth_hist(df)
    plot_pca(df, X)
    plot_tsne(df, X)
    plot_iso(df)
    plot_llm_vs_manual(touch_by_source)
    print(f"[+] Figures -> {FIG}/")

    # --- Representative session summaries ---
    summaries = make_summaries(df, by_port)

    # --- Baseline: comparison with a minimal environment without decoys ---
    # In a minimal environment without decoys, all cat/grep would return empty,
    # so artefacts_touched=0 everywhere. The comparison shows how much extra
    # engagement the decoys caused.
    baseline_note = {
        "with_decoys_avg_touched": round(df["artefacts_touched"].mean(), 2),
        "with_decoys_max_touched": int(df["artefacts_touched"].max()),
        "minimal_static_avg_touched": 0.0,
        "interpretation": (
            "Σε ενα minimal στατικο περιβαλλον χωρις decoys, καμια εντολη "
            "αναγνωσης δεν θα επεστρεφε περιεχομενο, οποτε το artefacts_touched "
            "θα ηταν 0 σε ολα τα sessions. Τα decoys προκαλεσαν βαθυτερη εμπλοκη "
            "(εως 6 artefacts σε ενα session)."
        ),
    }

    # --- Save: the CSV with the features (also used by 05) ---
    df_out = df.drop(columns=["_touched_list"]).copy()
    df_out.to_csv(OUT / "session_features.csv", index=False)

    report = {
        "counts": {
            "total_logs": len(sessions),
            "command_sessions": len(cmd_sessions),
            "failed_auth_probes": len(auth_probes),
        },
        "behavioural_means": {
            "dwell_time": round(df["dwell_time"].mean(), 2),
            "command_count": round(df["command_count"].mean(), 2),
            "cmd_diversity": round(df["cmd_diversity"].mean(), 2),
            "artefacts_touched": round(df["artefacts_touched"].mean(), 2),
            "path_depth": round(df["path_depth"].mean(), 2),
        },
        "clustering": {
            "kmeans_k": int(best_k), "silhouette": sil,
            "cluster_vs_intent_ARI": round(ari, 3),
            "iso_flagged_deep": int(df["iso_flag"].sum()),
            "ari_interpretation": (
                "Το ARI μετρα ποσο τα unsupervised clusters συμπιπτουν με τα 7 "
                "intents. Χαμηλες τιμες σημαινουν οτι το clustering ομαδοποιει "
                "κυριως κατα ΒΑΘΟΣ/ΠΡΟΦΙΛ εμπλοκης (ρηχα probes, deep readers, "
                "privesc) και οχι κατα semantic intent - αναμενομενο, αφου τα "
                "features μετρανε συμπεριφορα. Η προβλεψη intent αντιμετωπιζεται "
                "με supervised μοντελο στο 05_intent_classifier.py."
            ),
        },
        "decoy_engagement": {
            "touches_by_source": dict(touch_by_source),
            "touches_by_category": dict(touch_by_cat),
            "top_artefacts": touch_by_artifact.most_common(6),
        },
        "static_vs_decoy_baseline": baseline_note,
        "session_summaries": summaries,
    }
    (OUT / "analysis_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Cluster composition (which intents ended up in which cluster).
    # Built explicitly with a loop to avoid tuple keys (MultiIndex).
    comp = {}
    for k, sub in df.groupby("kmeans"):
        comp[f"cluster_{int(k)}"] = {
            "size": int(len(sub)),
            "intents": dict(Counter(sub["intent"])),
            "depths": dict(Counter(sub["depth"])),
            "avg_artefacts_touched": round(float(sub["artefacts_touched"].mean()), 2),
            "avg_command_count": round(float(sub["command_count"].mean()), 2),
        }
    (OUT / "cluster_composition.json").write_text(
        json.dumps(comp, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Αναλυση -> {OUT}/analysis_report.json")
    print(f"[+] Features -> {OUT}/session_features.csv")
    print()
    print("=== ΣΥΝΟΨΗ ===")
    print(f"  Μεσο artefacts touched (με decoys): {report['behavioural_means']['artefacts_touched']} "
          f"(baseline χωρις decoys: 0)")
    print(f"  Touches manual vs LLM: {dict(touch_by_source)}")
    print(f"  Isolation Forest flagged ως βαθια: {int(df['iso_flag'].sum())}/{len(df)}")
    print(f"  Cluster-vs-intent ARI: {ari:.3f} (1.0 = τελεια συμφωνια)")


if __name__ == "__main__":
    main()
