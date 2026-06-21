# Power BI Setup Guide — Insider Risk Monitoring System

## Dashboard Pages

### Page 1: Executive Overview
**Purpose:** C-suite / security leadership summary

**KPI Cards:**
- Total Employees
- Total Access Events  
- High Risk Events (score ≥ 60)
- Average Risk Score

**Visuals:**
1. Monthly Risk Trend — stacked bar (total events + high-risk events overlay)
2. Risk Level Distribution — donut chart
3. Access Location Breakdown — horizontal bar
4. Active Alerts — table with conditional formatting

---

### Page 2: Risk Analytics
**Purpose:** Security analyst deep-dive

**Visuals:**
1. Risk by Department — horizontal bar chart (avg risk score)
2. Data Downloads by Department — horizontal bar (MB)
3. Monthly Risk Trend — dual-axis line chart (events + avg score)
4. Action Type Distribution — bar chart
5. Sensitivity Level Breakdown — bar chart with % labels

---

### Page 3: Investigation Dashboard
**Purpose:** Incident response and threat investigation

**Tables:**
1. Top Risk Employees — sortable, with risk score bar, risk level badge
2. High Download Activity — ranked list with volume bars
3. Suspicious Access Records — filtered to score ≥ 70
4. After-Hours Pattern — per-employee after-hours %

---

## Data Model Setup

### Step 1: Load CSVs
Get Data → Text/CSV → load all files from `/data/`:
- `employees.csv`
- `access_logs_enriched.csv`
- `employee_risk_scores.csv`
- `monthly_trend.csv`
- `department_summary.csv`

### Step 2: Create Relationships

```
employees [employee_id] ──1:M──► access_logs_enriched [employee_id]
employees [employee_id] ──1:1──► employee_risk_scores [employee_id]
```

Set cross-filter direction: Single (employees → logs)

### Step 3: Data Types
Ensure these columns are set correctly:
- `timestamp`, `date` → Date/Time
- `download_size_mb`, `rule_score`, `final_risk_score` → Decimal Number
- `is_after_hours`, `is_weekend`, `access_failed`, `vpn_used` → True/False

---

## DAX Measures

```dax
-- ─── KPI MEASURES ───────────────────────────────────────────

Total Employees = DISTINCTCOUNT(employees[employee_id])

Total Access Events = COUNTROWS(access_logs_enriched)

High Risk Events = 
CALCULATE(
    COUNTROWS(access_logs_enriched),
    access_logs_enriched[rule_score] >= 60
)

Avg Risk Score = AVERAGE(access_logs_enriched[rule_score])

High Risk Rate = 
DIVIDE(
    [High Risk Events],
    [Total Access Events],
    0
)

-- ─── RISK LEVEL ──────────────────────────────────────────────

Critical Employees = 
CALCULATE(
    COUNTROWS(employee_risk_scores),
    employee_risk_scores[risk_level] = "Critical"
)

High Risk Employees = 
CALCULATE(
    COUNTROWS(employee_risk_scores),
    employee_risk_scores[risk_level] IN {"Critical", "High"}
)

ML Anomalies Detected = 
CALCULATE(
    COUNTROWS(employee_risk_scores),
    employee_risk_scores[is_anomaly] = TRUE()
)

-- ─── ACCESS PATTERNS ─────────────────────────────────────────

After Hours Events = 
CALCULATE(
    COUNTROWS(access_logs_enriched),
    access_logs_enriched[is_after_hours] = TRUE()
)

After Hours Rate = 
DIVIDE([After Hours Events], [Total Access Events], 0)

Weekend Events = 
CALCULATE(
    COUNTROWS(access_logs_enriched),
    access_logs_enriched[is_weekend] = TRUE()
)

Failed Access Attempts = 
CALCULATE(
    COUNTROWS(access_logs_enriched),
    access_logs_enriched[access_failed] = TRUE()
)

Suspicious Location Events = 
CALCULATE(
    COUNTROWS(access_logs_enriched),
    access_logs_enriched[location] IN {"Foreign_IP", "Proxy", "Unknown"}
)

-- ─── DATA EXFILTRATION ────────────────────────────────────────

Total Downloads MB = SUM(access_logs_enriched[download_size_mb])

High Risk Downloads MB = 
CALCULATE(
    SUM(access_logs_enriched[download_size_mb]),
    access_logs_enriched[location] IN {"Foreign_IP", "Proxy"}
)

Exfiltration Risk Score = 
DIVIDE([High Risk Downloads MB], [Total Downloads MB], 0)

-- ─── CONDITIONAL FORMATTING ──────────────────────────────────

Risk Level Color = 
SWITCH(
    SELECTEDVALUE(employee_risk_scores[risk_level]),
    "Critical", "#E24B4A",
    "High",     "#EF9F27",
    "Medium",   "#639922",
    "Low",      "#378ADD",
    "#888780"
)

Risk Score Color = 
VAR Score = SELECTEDVALUE(employee_risk_scores[final_risk_score])
RETURN
    SWITCH(
        TRUE(),
        Score >= 70, "#E24B4A",
        Score >= 50, "#EF9F27",
        Score >= 30, "#639922",
        "#378ADD"
    )
```

---

## Report Filters & Slicers

Recommended slicers for each page:

**Page 1 (Executive):**
- Date range slicer (timestamp)
- Department multi-select

**Page 2 (Risk Analytics):**
- Department
- Risk Level
- Date range

**Page 3 (Investigation):**
- Risk Level (Critical/High pre-filtered)
- Department
- Employee search (contains filter on full_name)
- Date range

---

## Conditional Formatting Rules

### Risk Score Bar (employee table)
- Data bar: min = 0, max = 100
- Color: gradient Red (#E24B4A) for high, Blue (#378ADD) for low

### Risk Level Background
| Value | Background | Text |
|---|---|---|
| Critical | #FCEBEB | #A32D2D |
| High | #FAEEDA | #854F0B |
| Medium | #EAF3DE | #3B6D11 |
| Low | #E6F1FB | #185FA5 |

### Download Size Bars
- Color: Red if location = Foreign_IP or Proxy, Blue otherwise
