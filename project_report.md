# Project Report: Insider Risk Monitoring System

**Version:** 1.0  
**Period Covered:** FY 2024 (January – December)  
**Dataset:** 10,000 synthetic access log events · 150 employees

---

## Executive Summary

This report presents findings from the Insider Risk Monitoring System, a data-driven security analytics pipeline that combines rule-based scoring and machine learning (Isolation Forest) to detect potential insider threats across an organization's access logs.

Three employees reached **Critical** risk classification during FY 2024, exhibiting patterns consistent with systematic data exfiltration: 100% after-hours access, exclusive use of foreign IP addresses, and bulk downloads of Highly Confidential resources totaling 47,434 MB combined. Additionally, 12 employees were flagged as behavioral anomalies by the ML model, warranting investigation.

---

## 1. Dataset Overview

| Metric | Value |
|---|---|
| Total employees monitored | 150 |
| Departments | 7 |
| Total access events analyzed | 10,000 |
| Date range | 2024-01-01 to 2024-12-31 |
| Unique resource types | 15 |
| Data volume processed | ~114,900 MB in downloads |

---

## 2. Risk Score Distribution

| Risk Level | Employees | Percentage |
|---|---|---|
| Critical | 3 | 2.0% |
| High | 2 | 1.3% |
| Medium | 136 | 90.7% |
| Low | 9 | 6.0% |

### Interpretation

The majority of employees (90.7%) fall in the Medium band — consistent with a workforce operating mostly within expected parameters but generating occasional borderline events. The 5 employees at High or Critical level represent actionable investigation targets.

---

## 3. Critical Risk Employees

### EMP1075 — Jason Lewis (Engineering)
- **Final Risk Score:** 97.55 / 100
- **ML Anomaly Score:** 98.4 (flagged as anomaly)
- **Pattern:** 100% of accesses occurred after hours, exclusively from foreign IP addresses. Downloaded 14,673 MB, primarily from Merger_Document, Salary_Data, and Security_Config resources.
- **Recommended Action:** Immediate account suspension pending investigation. Engage Legal and HR.

### EMP1046 — Jasmin West (Engineering)
- **Final Risk Score:** 96.67 / 100
- **ML Anomaly Score:** 97.1 (flagged as anomaly)
- **Pattern:** Highest data exfiltration volume: 16,862 MB. All events from foreign IP or proxy. Accessed Highly Confidential resources including HR_Database and Executive_Email exclusively via DOWNLOAD and COPY actions.
- **Recommended Action:** Immediate account suspension. Device forensics recommended.

### EMP1051 — Steven Flynn (HR)
- **Final Risk Score:** 96.46 / 100
- **ML Anomaly Score:** 96.8 (flagged as anomaly)
- **Pattern:** 15,899 MB downloaded, 100% after hours, 56 foreign IP events. HR department employee accessing Merger_Document and Financial_Report resources outside departmental scope.
- **Recommended Action:** Immediate account suspension. HR self-access audit required.

---

## 4. Department Risk Analysis

| Department | Avg Risk Score | High-Risk Events | Total Downloads (MB) |
|---|---|---|---|
| HR | 64.8 | 305 | 18,370 |
| Engineering | 54.7 | 968 | 46,737 |
| IT | 51.4 | 299 | 6,803 |
| Sales | 49.8 | 679 | 15,829 |
| Legal | 49.4 | 224 | 5,388 |
| Finance | 49.0 | 442 | 10,976 |
| Operations | 49.3 | 407 | 10,798 |

**Key insight:** HR has the highest average risk score (64.8) despite being the second-smallest department. This is driven primarily by EMP1051. Engineering's high download volume (46,737 MB) is partly explained by the two Critical-level employees in that department.

---

## 5. Access Pattern Analysis

### Time-of-Day
- **After-hours events:** 4,290 (42.9% of all events)
- **Weekend events:** 1,847 (18.5% of all events)
- Majority of normal employees access systems primarily between 09:00 and 18:00. The three Critical employees exclusively accessed systems during off-hours.

### Location
- **Office (baseline):** 53.0% of events
- **Suspicious locations (Foreign_IP + Proxy + Unknown):** 13.5% of events — 1,351 events total
- Foreign IP events are heavily concentrated in the three Critical employees (180 events combined out of 446 total)

### Resource Sensitivity
- **Highly Confidential accessed:** 40.9% of all events — significantly above expected levels
- **Confidential:** 33.5%
- Combined, 74.4% of all accesses involve sensitive resources, indicating either overly broad access controls or active exfiltration

---

## 6. Data Exfiltration Indicators

### Volume Thresholds Exceeded
- 3 employees each exceeded 10,000 MB total download volume — a significant red flag
- Industry benchmark: >500 MB/month per employee warrants review
- 5 employees exceed 500 MB/month average

### Single-Event Downloads (>100MB)
Multiple single-session downloads exceeding 100 MB were recorded from Critical employees. Combined with after-hours timing and foreign IP origin, these events constitute strong exfiltration indicators.

---

## 7. ML Model Performance

**Algorithm:** Isolation Forest  
**Contamination parameter:** 8% (expected anomaly rate)  
**Features used:** 13 behavioral aggregates  
**Employees flagged:** 12

The model successfully identified all three Critical employees as anomalies, plus 9 additional employees showing anomalous behavior that may warrant softer interventions (enhanced monitoring, access reviews).

---

## 8. Recommendations

### Immediate Actions
1. Suspend accounts for EMP1075, EMP1046, EMP1051 pending investigation
2. Initiate device forensics for all three Critical employees
3. Escalate to Legal and HR for EMP1051 (HR self-access)

### Short-Term Controls (30 days)
1. Implement geo-blocking rules: flag/block access from foreign IPs without prior approval
2. Add DLP (Data Loss Prevention) controls on downloads exceeding 500 MB
3. Require MFA challenge for after-hours access to Highly Confidential resources
4. Review and tighten access control lists — 74.4% Highly Confidential access rate suggests over-permissioning

### Strategic Improvements (90 days)
1. Deploy UEBA (User and Entity Behavior Analytics) for real-time monitoring
2. Integrate with SIEM (Splunk/Sentinel) for automated alert routing
3. Implement monthly access recertification for Highly Confidential resources
4. Establish baseline behavioral profiles for each role to improve anomaly precision

---

## 9. Limitations

- Dataset is synthetic — real-world distributions may differ
- No session-chaining: each log event is treated independently
- Isolation Forest is unsupervised — requires periodic calibration against confirmed incidents
- No network traffic metadata (packet captures, DNS logs) included

---

## 10. Technical Appendix

### Risk Score Formula
```
Final Score = (avg_rule_score × 0.60) + (anomaly_score × 0.40)
```

### Isolation Forest Features
```python
FEATURE_COLS = [
    "total_events", "after_hours_pct", "failed_pct",
    "total_download_mb", "max_single_download_mb",
    "highly_conf_accesses", "foreign_ip_events",
    "proxy_events", "delete_events", "share_events",
    "high_sens_pct", "avg_rule_score", "max_rule_score",
]
```

### Key SQL Queries Used in Analysis
- Q04: Top 20 Highest Risk Employees
- Q05: ML Anomaly Employees
- Q12: Top Data Downloaders
- Q15: Highly Confidential Resource Access
- Q20: Monthly Risk Escalation Trend
- Q24: Suspicious Sequence Detection

---

*This report was generated by the Insider Risk Monitoring System v1.0.*
