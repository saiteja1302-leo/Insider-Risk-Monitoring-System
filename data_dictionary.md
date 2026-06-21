# Data Dictionary — Insider Risk Monitoring System

## Table: employees

| Column | Data Type | Nullable | Example | Description |
|---|---|---|---|---|
| employee_id | VARCHAR(10) | NO | EMP1075 | Primary key. Format: EMP + 4-digit number |
| full_name | VARCHAR(100) | NO | Jason Lewis | Employee's display name |
| email | VARCHAR(150) | NO | jlewis@corp.com | Corporate email address |
| department | VARCHAR(50) | NO | Engineering | One of: Finance, Engineering, HR, Sales, Legal, Operations, IT |
| role | VARCHAR(80) | NO | Senior Engineer | Job title within department |
| hire_date | DATE | NO | 2018-03-14 | ISO 8601 date of employment start |
| manager_id | VARCHAR(10) | YES | EMP1020 | FK → employees.employee_id; NULL for top-level |
| employment_status | VARCHAR(20) | NO | Active | One of: Active, On_Leave, Terminating |

---

## Table: access_logs

| Column | Data Type | Nullable | Example | Description |
|---|---|---|---|---|
| log_id | VARCHAR(12) | NO | LOG1000000 | Primary key. Format: LOG + 7-digit number |
| employee_id | VARCHAR(10) | NO | EMP1075 | FK → employees.employee_id |
| department | VARCHAR(50) | NO | Engineering | Denormalized dept from employees table |
| timestamp | DATETIME | NO | 2024-07-15 02:34:11 | Full event timestamp (UTC) |
| date | DATE | NO | 2024-07-15 | Date portion of timestamp |
| hour | INT | NO | 2 | Hour of day, 0–23 |
| day_of_week | VARCHAR(10) | NO | Monday | Full weekday name |
| is_weekend | BOOLEAN | NO | FALSE | TRUE if Saturday or Sunday |
| is_after_hours | BOOLEAN | NO | TRUE | TRUE if hour < 9 or hour >= 18 |
| resource_type | VARCHAR(50) | NO | HR_Database | See Resource Types below |
| sensitivity_level | VARCHAR(30) | NO | Highly Confidential | See Sensitivity Levels below |
| action | VARCHAR(20) | NO | DOWNLOAD | See Actions below |
| location | VARCHAR(20) | NO | Foreign_IP | See Locations below |
| download_size_mb | FLOAT | NO | 247.83 | MB transferred; 0 if action is VIEW or EDIT |
| session_duration_min | INT | NO | 23 | Length of access session in minutes |
| access_failed | BOOLEAN | NO | FALSE | TRUE if authentication or authorization failed |
| ip_address | VARCHAR(15) | NO | 185.42.97.13 | Source IPv4 address |
| device_type | VARCHAR(20) | NO | Laptop | One of: Laptop, Desktop, Mobile, Unknown |
| vpn_used | BOOLEAN | NO | FALSE | TRUE if location == 'VPN' |

---

## Table: employee_risk_scores

| Column | Data Type | Description |
|---|---|---|
| employee_id | VARCHAR(10) | PK, FK → employees |
| total_events | INT | Total access events in period |
| after_hours_events | INT | Count of after-hours events |
| weekend_events | INT | Count of weekend events |
| failed_attempts | INT | Count of failed access attempts |
| total_download_mb | FLOAT | Total MB downloaded/copied/shared |
| max_single_download_mb | FLOAT | Largest single-event download |
| highly_conf_accesses | INT | Count of Highly Confidential resource accesses |
| foreign_ip_events | INT | Count of events from foreign IP addresses |
| proxy_events | INT | Count of events via proxy |
| delete_events | INT | Count of DELETE actions |
| share_events | INT | Count of SHARE actions |
| unique_resources | INT | Number of distinct resource types accessed |
| avg_rule_score | FLOAT | Mean rule-based risk score (0–100) |
| max_rule_score | FLOAT | Highest single-event rule score |
| sum_rule_score | FLOAT | Sum of all rule scores |
| after_hours_pct | FLOAT | Ratio of after-hours events (0–1) |
| failed_pct | FLOAT | Ratio of failed attempts (0–1) |
| high_sens_pct | FLOAT | Ratio of Highly Confidential accesses (0–1) |
| anomaly_score | FLOAT | Isolation Forest anomaly score (0–100; higher = more anomalous) |
| is_anomaly | BOOLEAN | TRUE if flagged as anomaly by Isolation Forest |
| final_risk_score | FLOAT | Composite risk score: 60% rule + 40% ML (0–100) |
| risk_level | VARCHAR(10) | Critical / High / Medium / Low |

---

## Reference: Resource Types

| Resource Type | Sensitivity | Description |
|---|---|---|
| Financial_Report | Confidential | Quarterly/annual financial statements |
| HR_Database | Highly Confidential | Employee PII, performance records |
| Source_Code | Internal | Company proprietary source code |
| Customer_Data | Confidential | Customer PII and purchase history |
| Legal_Document | Confidential | Contracts, NDAs, litigation documents |
| Executive_Email | Highly Confidential | C-suite communications |
| Product_Roadmap | Confidential | Future product plans |
| Employee_Records | Highly Confidential | HR files including salaries |
| Security_Config | Highly Confidential | Network/system security configurations |
| Merger_Document | Highly Confidential | M&A, due diligence documents |
| Salary_Data | Highly Confidential | Compensation data |
| IP_Document | Confidential | Patents, trade secrets |
| General_File | Public | General office documents |
| Internal_Wiki | Internal | Team knowledge base |
| Meeting_Notes | Internal | Meeting minutes, action items |

---

## Reference: Sensitivity Levels (ordered by severity)

| Level | Risk Weight | Description |
|---|---|---|
| Highly Confidential | +30 | Restricted; access should be minimal and audited |
| Confidential | +20 | Business sensitive; limited distribution |
| Internal | +10 | Employees only; not for external sharing |
| Public | +2 | No restrictions |

---

## Reference: Actions

| Action | Risk Weight | Description |
|---|---|---|
| DELETE | +25 | Permanent removal of a resource |
| SHARE | +20 | Shared externally or with other teams |
| COPY | +18 | Duplicated to another location |
| DOWNLOAD | +15 | Saved to local device |
| PRINT | +12 | Printed to physical copy |
| EDIT | +8 | Modified in place |
| VIEW | +3 | Read-only access |

---

## Reference: Locations

| Location | Risk Weight | Description |
|---|---|---|
| Foreign_IP | +35 | Source IP geolocates to foreign country |
| Proxy | +28 | Access via anonymizing proxy |
| Unknown | +22 | IP could not be resolved or categorized |
| Home | +8 | Matches employee's registered home IP |
| VPN | +5 | Corporate VPN — expected for remote work |
| Office | 0 | Corporate network — baseline |
