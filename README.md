# Insider Risk Monitoring System

> End-to-end threat detection pipeline: SQL · Python · Isolation Forest · Power BI

---

## Overview

Organizations generate millions of employee access logs daily. Security teams need a way to identify suspicious activities such as after-hours access, excessive data downloads, access to confidential files, and unusual behavior patterns. This project builds a production-ready risk-scoring system and interactive dashboard to detect potential insider threats.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA PIPELINE                               │
│                                                                 │
│  Raw Logs  ──►  Python ETL  ──►  Risk Engine  ──►  Power BI   │
│               (Faker/Pandas)    (Rules + ML)      Dashboard    │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌──────────┐  │
│  │Synthetic │   │generate_ │   │risk_      │   │3-page    │  │
│  │Dataset   │──►│dataset.py│──►│scoring.py │──►│dashboard │  │
│  │10K rows  │   │          │   │           │   │          │  │
│  └──────────┘   └──────────┘   └───────────┘   └──────────┘  │
│                                      │                         │
│                              ┌───────┴────────┐               │
│                              │  SQL Queries   │               │
│                              │  (25 queries)  │               │
│                              └────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
insider-risk-system/
├── data/
│   ├── employees.csv                  # 150 synthetic employees
│   ├── access_logs.csv                # 10,000 raw access events
│   ├── access_logs_enriched.csv       # Logs with risk scores
│   ├── employee_risk_scores.csv       # Final employee risk profiles
│   ├── monthly_trend.csv              # Monthly aggregates
│   └── department_summary.csv         # Department-level summary
│
├── python/
│   ├── generate_dataset.py            # Synthetic data generator
│   └── risk_scoring.py                # Risk engine + ML anomaly detection
│
├── sql/
│   └── risk_queries.sql               # 25 production SQL queries
│
├── docs/
│   ├── data_dictionary.md             # Column definitions
│   ├── er_diagram.md                  # Entity relationships
│   └── architecture.md                # System architecture
│
└── README.md                          # This file
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install pandas numpy scikit-learn faker openpyxl matplotlib seaborn
```

### 2. Generate synthetic dataset
```bash
python python/generate_dataset.py
```
Outputs: `data/employees.csv` and `data/access_logs.csv`

### 3. Run risk scoring engine
```bash
python python/risk_scoring.py
```
Outputs enriched CSVs with risk scores and ML anomaly flags.

### 4. Load in Power BI
- Open Power BI Desktop
- Get Data → Text/CSV → select files from `data/`
- Create relationships on `employee_id`
- Apply DAX measures (see below)

### 5. Run SQL queries
```bash
# SQLite example
sqlite3 risk.db < sql/risk_queries.sql
```

---

## Dataset Schema

### employees.csv
| Column | Type | Description |
|---|---|---|
| employee_id | VARCHAR | Primary key (EMP1000-EMP1149) |
| full_name | VARCHAR | Synthetic employee name |
| email | VARCHAR | Corporate email address |
| department | VARCHAR | One of 7 departments |
| role | VARCHAR | Job title |
| hire_date | DATE | Employment start date |
| manager_id | VARCHAR | Foreign key → employee_id |
| employment_status | VARCHAR | Active / On_Leave / Terminating |

### access_logs.csv
| Column | Type | Description |
|---|---|---|
| log_id | VARCHAR | Unique event ID |
| employee_id | VARCHAR | FK → employees |
| department | VARCHAR | Employee's department |
| timestamp | DATETIME | Full event datetime |
| date | DATE | Event date |
| hour | INT | Hour of day (0-23) |
| day_of_week | VARCHAR | Day name |
| is_weekend | BOOLEAN | True if Saturday/Sunday |
| is_after_hours | BOOLEAN | True if outside 09:00-18:00 |
| resource_type | VARCHAR | Type of resource accessed |
| sensitivity_level | VARCHAR | Public / Internal / Confidential / Highly Confidential |
| action | VARCHAR | VIEW / DOWNLOAD / EDIT / DELETE / SHARE / PRINT / COPY |
| location | VARCHAR | Office / Home / VPN / Unknown / Foreign_IP / Proxy |
| download_size_mb | FLOAT | Data transferred in MB |
| session_duration_min | INT | Session length in minutes |
| access_failed | BOOLEAN | True if authentication failed |
| ip_address | VARCHAR | Source IP address |
| device_type | VARCHAR | Laptop / Desktop / Mobile / Unknown |
| vpn_used | BOOLEAN | True if VPN connection |

---

## Risk Scoring Methodology

### Rule-Based Scoring (60% weight)

| Factor | Points |
|---|---|
| Highly Confidential resource | +30 |
| After-hours access | +20 |
| Confidential resource | +20 |
| DELETE action | +25 |
| SHARE action | +20 |
| COPY action | +18 |
| DOWNLOAD action | +15 |
| Foreign IP location | +35 |
| Proxy location | +28 |
| Unknown location | +22 |
| Weekend access | +15 |
| Download > 100MB | +25 |
| Download > 50MB | +15 |
| Failed authentication | +10 |

### ML Anomaly Detection (40% weight)

Uses **Isolation Forest** with 13 behavioral features:
- Total events, after-hours percentage, failed access rate
- Total/max download volume, highly-confidential access count
- Foreign IP events, proxy events, delete/share event counts
- High-sensitivity access percentage, avg/max rule score

The algorithm flags the most isolated employees as anomalies (contamination = 8%).

### Final Risk Score
```
Final Score = (Avg Rule Score × 0.60) + (ML Anomaly Score × 0.40)
```

| Score | Risk Level |
|---|---|
| ≥ 70 | Critical |
| 50–69 | High |
| 30–49 | Medium |
| < 30 | Low |

---

## Power BI DAX Measures

```dax
-- High Risk Event Rate
High Risk Rate = 
DIVIDE(
    CALCULATE(COUNTROWS(access_logs_enriched), access_logs_enriched[rule_score] >= 60),
    COUNTROWS(access_logs_enriched)
)

-- After-Hours Access %
After Hours Pct = 
DIVIDE(
    CALCULATE(COUNTROWS(access_logs_enriched), access_logs_enriched[is_after_hours] = TRUE()),
    COUNTROWS(access_logs_enriched)
)

-- Total Data Exfiltration Risk (MB)
Exfiltration Risk MB = 
CALCULATE(
    SUM(access_logs_enriched[download_size_mb]),
    access_logs_enriched[location] IN {"Foreign_IP", "Proxy", "Unknown"}
)

-- Employees Above Risk Threshold
Critical Employees = 
CALCULATE(
    COUNTROWS(employee_risk_scores),
    employee_risk_scores[risk_level] IN {"Critical", "High"}
)
```

---

## SQL Query Library (25 Queries)

| # | Query | Purpose |
|---|---|---|
| Q01 | Executive Dashboard Summary | KPI overview |
| Q02 | Risk Level Distribution | Workforce risk breakdown |
| Q03 | Daily Active Users & Risk Trend | 30-day view |
| Q04 | Top 20 Highest Risk Employees | Priority investigation list |
| Q05 | ML Anomaly Employees | Isolation Forest flagged |
| Q06 | Employee vs Dept Average | Peer comparison |
| Q07 | Terminating Employees | Departing high-risk employees |
| Q08 | After-Hours by Department | Dept comparison |
| Q09 | Hourly Access Heat Map | Time pattern analysis |
| Q10 | Suspicious Location Access | Foreign IP & proxy |
| Q11 | Weekend Warriors | Weekend access analysis |
| Q12 | Top Data Downloaders | Exfiltration candidates |
| Q13 | Single-Event Large Downloads | >100MB events |
| Q14 | File Share/Copy Cascade | Same-day bulk sharing |
| Q15 | Highly Confidential Access Log | Sensitive resource tracking |
| Q16 | Cross-Department Access | Unusual resource access |
| Q17 | Repeated Auth Failures | Brute-force indicators |
| Q18 | Brute-Force Pattern Detection | Per-day failure windows |
| Q19 | Department Risk Leaderboard | Dept-level comparison |
| Q20 | Monthly Risk Escalation | 12-month trend |
| Q21 | Week-Over-Week Risk Change | WoW analysis with LAG() |
| Q22 | Full Audit Trail | Single employee investigation |
| Q23 | Peer Comparison | Outlier detection |
| Q24 | Suspicious Sequence | After-hours + confidential + large download |
| Q25 | Delete Event Analysis | Data destruction indicators |

---

## Key Findings (FY 2024)

- **3 Critical risk employees** detected — all exhibiting 100% after-hours access and large-scale downloads from foreign IPs
- **33.2%** of all access events classified as high-risk (score ≥ 60)
- **40.9%** of events involved Highly Confidential resources
- **HR department** carries highest average risk score (64.8) despite smaller headcount
- **Engineering** accounts for the largest data volume (46,737 MB total downloads)
- **12 employees** flagged as behavioral anomalies by Isolation Forest

---

## Extending the Project

1. **Real-time pipeline**: Replace CSV ingestion with Kafka + Spark Streaming
2. **Alert system**: Connect Power BI alerts to Teams/Slack webhooks
3. **UEBA integration**: Add user entity behavior analytics features (typing speed, mouse patterns)
4. **SIEM connector**: Export to Splunk or Microsoft Sentinel
5. **Explainable AI**: Add SHAP values to explain individual risk scores

---

## License

MIT — free for commercial and educational use.
