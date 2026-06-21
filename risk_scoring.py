"""
Insider Risk Monitoring System - Risk Scoring Engine
Advanced risk scoring using rule-based scoring + Isolation Forest anomaly detection
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os, warnings
warnings.filterwarnings("ignore")

DATA_DIR = "/home/claude/insider-risk-system/data"

# ─── Load Data ────────────────────────────────────────────────────────────────
def load_data():
    emp = pd.read_csv(f"{DATA_DIR}/employees.csv")
    log = pd.read_csv(f"{DATA_DIR}/access_logs.csv", parse_dates=["timestamp","date"])
    return emp, log

# ─── Rule-Based Risk Scoring ──────────────────────────────────────────────────
SENS_SCORE  = {"Highly Confidential": 30, "Confidential": 20, "Internal": 10, "Public": 2}
ACTION_SCORE= {"DELETE": 25, "SHARE": 20, "COPY": 18, "DOWNLOAD": 15, "PRINT": 12, "EDIT": 8, "VIEW": 3}
LOC_SCORE   = {"Foreign_IP": 35, "Proxy": 28, "Unknown": 22, "Home": 8, "VPN": 5, "Office": 0}

def compute_rule_score(row):
    score = 0
    score += SENS_SCORE.get(row["sensitivity_level"], 0)
    score += ACTION_SCORE.get(row["action"], 0)
    score += LOC_SCORE.get(row["location"], 0)
    if row["is_after_hours"]:  score += 20
    if row["is_weekend"]:      score += 15
    if row["access_failed"]:   score += 10
    if row["download_size_mb"] > 100: score += 25
    elif row["download_size_mb"] > 50:  score += 15
    elif row["download_size_mb"] > 10:  score += 8
    return min(score, 100)

# ─── Per-Employee Behavioural Aggregates ─────────────────────────────────────
def compute_employee_aggregates(log_df):
    agg = log_df.groupby("employee_id").agg(
        total_events           =("log_id","count"),
        after_hours_events     =("is_after_hours","sum"),
        weekend_events         =("is_weekend","sum"),
        failed_attempts        =("access_failed","sum"),
        total_download_mb      =("download_size_mb","sum"),
        max_single_download_mb =("download_size_mb","max"),
        highly_conf_accesses   =("sensitivity_level", lambda x: (x=="Highly Confidential").sum()),
        foreign_ip_events      =("location", lambda x: (x=="Foreign_IP").sum()),
        proxy_events           =("location", lambda x: (x=="Proxy").sum()),
        delete_events          =("action", lambda x: (x=="DELETE").sum()),
        share_events           =("action", lambda x: (x=="SHARE").sum()),
        unique_resources       =("resource_type","nunique"),
        avg_rule_score         =("rule_score","mean"),
        max_rule_score         =("rule_score","max"),
        sum_rule_score         =("rule_score","sum"),
    ).reset_index()

    agg["after_hours_pct"]  = agg["after_hours_events"] / agg["total_events"].clip(1)
    agg["failed_pct"]       = agg["failed_attempts"]    / agg["total_events"].clip(1)
    agg["high_sens_pct"]    = agg["highly_conf_accesses"]/ agg["total_events"].clip(1)
    return agg

# ─── Isolation Forest Anomaly Detection ──────────────────────────────────────
FEATURE_COLS = [
    "total_events","after_hours_pct","failed_pct","total_download_mb",
    "max_single_download_mb","highly_conf_accesses","foreign_ip_events",
    "proxy_events","delete_events","share_events","high_sens_pct",
    "avg_rule_score","max_rule_score",
]

def run_isolation_forest(agg_df):
    X = agg_df[FEATURE_COLS].fillna(0)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    iso = IsolationForest(n_estimators=200, contamination=0.08, random_state=42)
    iso.fit(Xs)
    scores    = iso.score_samples(Xs)          # lower = more anomalous
    preds     = iso.predict(Xs)                # -1 = anomaly
    # Convert to 0-100 (higher = more anomalous)
    norm = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
    agg_df["anomaly_score"]  = (norm * 100).round(2)
    agg_df["is_anomaly"]     = preds == -1
    return agg_df

# ─── Final Employee Risk Score ────────────────────────────────────────────────
def compute_final_risk(agg_df):
    rule_norm   = agg_df["avg_rule_score"]  / 100
    anomaly_norm= agg_df["anomaly_score"]   / 100
    # Weighted composite: 60% rule-based, 40% ML anomaly
    composite   = (rule_norm * 0.60 + anomaly_norm * 0.40) * 100

    # Severity thresholds
    def label(s):
        if   s >= 70: return "Critical"
        elif s >= 50: return "High"
        elif s >= 30: return "Medium"
        else:         return "Low"

    agg_df["final_risk_score"] = composite.round(2)
    agg_df["risk_level"]       = composite.apply(label)
    return agg_df

# ─── Enrich Access Logs ───────────────────────────────────────────────────────
def enrich_logs(log_df, agg_df):
    log_df = log_df.merge(
        agg_df[["employee_id","final_risk_score","risk_level","anomaly_score","is_anomaly"]],
        on="employee_id", how="left"
    )
    return log_df

# ─── Save Outputs ─────────────────────────────────────────────────────────────
def save_outputs(emp_df, agg_df, log_df):
    merged_emp = emp_df.merge(
        agg_df[["employee_id","total_events","total_download_mb","after_hours_pct",
                "failed_pct","high_sens_pct","foreign_ip_events","avg_rule_score",
                "anomaly_score","final_risk_score","risk_level","is_anomaly"]],
        on="employee_id", how="left"
    )
    merged_emp.to_csv(f"{DATA_DIR}/employee_risk_scores.csv", index=False)
    log_df.to_csv(f"{DATA_DIR}/access_logs_enriched.csv", index=False)

    # Monthly trend
    log_df["month"] = pd.to_datetime(log_df["date"]).dt.to_period("M").astype(str)
    monthly = log_df.groupby("month").agg(
        total_events    =("log_id","count"),
        high_risk_events=("rule_score", lambda x: (x>=60).sum()),
        avg_risk_score  =("rule_score","mean"),
        total_downloads =("download_size_mb","sum"),
    ).reset_index()
    monthly.to_csv(f"{DATA_DIR}/monthly_trend.csv", index=False)

    # Department summary
    dept = log_df.groupby("department").agg(
        total_events     =("log_id","count"),
        avg_risk_score   =("rule_score","mean"),
        high_risk_events =("rule_score", lambda x:(x>=60).sum()),
        total_downloads  =("download_size_mb","sum"),
    ).reset_index()
    dept.to_csv(f"{DATA_DIR}/department_summary.csv", index=False)

    print(f"✓ employee_risk_scores.csv  → {len(merged_emp):,} rows")
    print(f"✓ access_logs_enriched.csv  → {len(log_df):,} rows")
    print(f"✓ monthly_trend.csv         → {len(monthly):,} rows")
    print(f"✓ department_summary.csv    → {len(dept):,} rows")

# ─── Summary Stats ────────────────────────────────────────────────────────────
def print_summary(emp_risk_df):
    print("\n═══ Risk Summary ═══")
    print(emp_risk_df["risk_level"].value_counts().to_string())
    print(f"\nTop 10 Riskiest Employees:")
    top10 = emp_risk_df.nlargest(10,"final_risk_score")[["employee_id","full_name","department","final_risk_score","risk_level"]]
    print(top10.to_string(index=False))

# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Loading data …")
    emp_df, log_df = load_data()

    print("Computing rule-based scores …")
    log_df["rule_score"] = log_df.apply(compute_rule_score, axis=1)

    print("Computing employee aggregates …")
    agg_df = compute_employee_aggregates(log_df)

    print("Running Isolation Forest …")
    agg_df = run_isolation_forest(agg_df)

    print("Computing final risk scores …")
    agg_df = compute_final_risk(agg_df)

    print("Enriching logs …")
    log_df = enrich_logs(log_df, agg_df)

    print("Saving outputs …")
    save_outputs(emp_df, agg_df, log_df)

    emp_risk = emp_df.merge(agg_df[["employee_id","final_risk_score","risk_level"]], on="employee_id")
    print_summary(emp_risk)
    print("\nRisk scoring complete.")
