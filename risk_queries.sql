-- ============================================================
-- INSIDER RISK MONITORING SYSTEM
-- Comprehensive SQL Query Library (25 Queries)
-- Compatible with: SQLite, PostgreSQL, SQL Server
-- ============================================================

-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 1: EXECUTIVE KPI QUERIES                       │
-- └─────────────────────────────────────────────────────────┘

-- Q01: Executive Dashboard Summary
SELECT
    COUNT(DISTINCT e.employee_id)                                  AS total_employees,
    COUNT(l.log_id)                                                AS total_access_events,
    SUM(CASE WHEN l.rule_score >= 60 THEN 1 ELSE 0 END)           AS high_risk_events,
    ROUND(AVG(l.rule_score), 2)                                    AS avg_risk_score,
    SUM(l.download_size_mb)                                        AS total_data_downloaded_mb,
    SUM(CASE WHEN l.access_failed = 1 THEN 1 ELSE 0 END)          AS total_failed_attempts,
    SUM(CASE WHEN l.is_after_hours = 1 THEN 1 ELSE 0 END)         AS after_hours_events
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id;


-- Q02: Risk Level Distribution
SELECT
    risk_level,
    COUNT(employee_id)                                             AS employee_count,
    ROUND(AVG(final_risk_score), 2)                               AS avg_score,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1)            AS pct_of_workforce
FROM employee_risk_scores
GROUP BY risk_level
ORDER BY avg_score DESC;


-- Q03: Daily Active Users and Risk Trend (Last 30 Days)
SELECT
    date,
    COUNT(DISTINCT employee_id)                                    AS active_users,
    COUNT(log_id)                                                  AS total_events,
    SUM(CASE WHEN rule_score >= 60 THEN 1 ELSE 0 END)             AS high_risk_events,
    ROUND(AVG(rule_score), 2)                                      AS avg_risk_score,
    ROUND(SUM(download_size_mb), 2)                                AS total_mb_downloaded
FROM access_logs_enriched
GROUP BY date
ORDER BY date DESC
LIMIT 30;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 2: EMPLOYEE RISK ANALYTICS                     │
-- └─────────────────────────────────────────────────────────┘

-- Q04: Top 20 Highest Risk Employees
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    e.role,
    e.employment_status,
    r.final_risk_score,
    r.risk_level,
    r.anomaly_score,
    r.total_events,
    ROUND(r.total_download_mb, 2)                                  AS total_download_mb,
    ROUND(r.after_hours_pct * 100, 1)                              AS after_hours_pct,
    r.foreign_ip_events,
    r.is_anomaly
FROM employee_risk_scores r
JOIN employees e ON r.employee_id = e.employee_id
ORDER BY r.final_risk_score DESC
LIMIT 20;


-- Q05: Employees with Anomalous Behaviour Detected by ML
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    e.role,
    r.anomaly_score,
    r.final_risk_score,
    r.risk_level,
    r.total_download_mb,
    r.foreign_ip_events,
    r.after_hours_pct,
    r.failed_pct
FROM employee_risk_scores r
JOIN employees e ON r.employee_id = e.employee_id
WHERE r.is_anomaly = 1
ORDER BY r.anomaly_score DESC;


-- Q06: Employee Behaviour Comparison vs Department Average
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    r.final_risk_score                                             AS employee_risk_score,
    ROUND(AVG(r2.final_risk_score) OVER (PARTITION BY e.department), 2) AS dept_avg_risk,
    r.final_risk_score - AVG(r2.final_risk_score) OVER (PARTITION BY e.department) AS deviation_from_dept_avg,
    r.total_download_mb,
    r.after_hours_pct
FROM employee_risk_scores r
JOIN employees e ON r.employee_id = e.employee_id
JOIN employee_risk_scores r2 ON r2.employee_id IN (
    SELECT employee_id FROM employees WHERE department = e.department
)
ORDER BY deviation_from_dept_avg DESC
LIMIT 30;


-- Q07: Terminating/At-Risk Employees With High Risk Scores
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    e.employment_status,
    e.hire_date,
    r.final_risk_score,
    r.risk_level,
    r.total_download_mb,
    r.highly_conf_accesses,
    r.share_events
FROM employee_risk_scores r
JOIN employees e ON r.employee_id = e.employee_id
WHERE e.employment_status IN ('Terminating','On_Leave')
  AND r.final_risk_score > 30
ORDER BY r.final_risk_score DESC;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 3: ACCESS PATTERN ANALYSIS                     │
-- └─────────────────────────────────────────────────────────┘

-- Q08: After-Hours Access by Department
SELECT
    department,
    COUNT(log_id)                                                   AS total_events,
    SUM(CASE WHEN is_after_hours = 1 THEN 1 ELSE 0 END)            AS after_hours_events,
    ROUND(SUM(CASE WHEN is_after_hours=1 THEN 1.0 ELSE 0 END)
          / COUNT(*) * 100, 1)                                      AS after_hours_pct,
    ROUND(AVG(rule_score), 2)                                       AS avg_risk_score
FROM access_logs_enriched
GROUP BY department
ORDER BY after_hours_pct DESC;


-- Q09: Hourly Access Heat Map (Anomaly Detection)
SELECT
    hour,
    day_of_week,
    COUNT(log_id)                                                   AS event_count,
    ROUND(AVG(rule_score), 2)                                       AS avg_risk_score,
    SUM(CASE WHEN rule_score >= 60 THEN 1 ELSE 0 END)              AS high_risk_count
FROM access_logs_enriched
GROUP BY hour, day_of_week
ORDER BY hour, 
    CASE day_of_week 
        WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2 WHEN 'Wednesday' THEN 3
        WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5 WHEN 'Saturday' THEN 6
        ELSE 7 END;


-- Q10: Suspicious Location Access (Foreign IPs / Proxy)
SELECT
    l.employee_id,
    e.full_name,
    e.department,
    l.location,
    COUNT(l.log_id)                                                 AS event_count,
    ROUND(AVG(l.rule_score), 2)                                     AS avg_risk_score,
    SUM(l.download_size_mb)                                         AS total_mb,
    COUNT(DISTINCT l.ip_address)                                    AS distinct_ips,
    MIN(l.timestamp)                                                AS first_seen,
    MAX(l.timestamp)                                                AS last_seen
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.location IN ('Foreign_IP','Proxy','Unknown')
GROUP BY l.employee_id, e.full_name, e.department, l.location
ORDER BY event_count DESC
LIMIT 30;


-- Q11: Weekend Warriors - Weekend Access Patterns
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    COUNT(l.log_id)                                                 AS weekend_events,
    ROUND(SUM(l.download_size_mb), 2)                              AS weekend_downloads_mb,
    ROUND(AVG(l.rule_score), 2)                                    AS avg_risk_score,
    SUM(CASE WHEN l.sensitivity_level='Highly Confidential' THEN 1 ELSE 0 END) AS highly_conf_accesses
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.is_weekend = 1
GROUP BY l.employee_id, e.full_name, e.department
HAVING COUNT(l.log_id) > 5
ORDER BY weekend_downloads_mb DESC;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 4: DATA EXFILTRATION DETECTION                 │
-- └─────────────────────────────────────────────────────────┘

-- Q12: Top Data Downloaders (Potential Exfiltration)
SELECT
    l.employee_id,
    e.full_name,
    e.department,
    e.employment_status,
    COUNT(l.log_id)                                                 AS download_events,
    ROUND(SUM(l.download_size_mb), 2)                              AS total_mb,
    ROUND(MAX(l.download_size_mb), 2)                              AS max_single_mb,
    ROUND(AVG(l.download_size_mb), 2)                              AS avg_mb_per_event,
    SUM(CASE WHEN l.sensitivity_level='Highly Confidential' THEN 1 ELSE 0 END) AS confidential_downloads
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.action IN ('DOWNLOAD','COPY','SHARE')
  AND l.download_size_mb > 0
GROUP BY l.employee_id, e.full_name, e.department, e.employment_status
ORDER BY total_mb DESC
LIMIT 20;


-- Q13: Single-Event Large Downloads (>100MB)
SELECT
    l.log_id,
    l.employee_id,
    e.full_name,
    e.department,
    l.timestamp,
    l.resource_type,
    l.sensitivity_level,
    l.action,
    l.location,
    ROUND(l.download_size_mb, 2)                                    AS download_size_mb,
    l.rule_score,
    l.is_after_hours,
    l.ip_address
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.download_size_mb > 100
ORDER BY l.download_size_mb DESC;


-- Q14: File Share / Copy Cascade (Same Employee, Same Day)
SELECT
    l.employee_id,
    e.full_name,
    e.department,
    CAST(l.timestamp AS DATE)                                       AS event_date,
    COUNT(l.log_id)                                                 AS share_copy_events,
    SUM(l.download_size_mb)                                        AS total_mb,
    COUNT(DISTINCT l.resource_type)                                AS unique_resources,
    MAX(l.rule_score)                                              AS max_risk_score
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.action IN ('SHARE','COPY')
GROUP BY l.employee_id, e.full_name, e.department, CAST(l.timestamp AS DATE)
HAVING share_copy_events >= 3
ORDER BY share_copy_events DESC;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 5: SENSITIVE RESOURCE MONITORING               │
-- └─────────────────────────────────────────────────────────┘

-- Q15: Highly Confidential Resource Access Log
SELECT
    l.log_id,
    l.timestamp,
    l.employee_id,
    e.full_name,
    e.department,
    e.role,
    l.resource_type,
    l.action,
    l.location,
    l.is_after_hours,
    l.download_size_mb,
    l.rule_score,
    l.risk_level
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.sensitivity_level = 'Highly Confidential'
  AND l.action IN ('DOWNLOAD','SHARE','COPY','DELETE')
ORDER BY l.rule_score DESC, l.timestamp DESC
LIMIT 50;


-- Q16: Cross-Department Resource Access (Unusual)
SELECT
    l.employee_id,
    e.full_name,
    e.department                                                    AS employee_dept,
    l.resource_type,
    COUNT(l.log_id)                                                 AS access_count,
    ROUND(AVG(l.rule_score), 2)                                    AS avg_risk_score,
    SUM(l.download_size_mb)                                        AS total_mb
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE 
    (e.department = 'Finance'      AND l.resource_type IN ('HR_Database','Employee_Records','Salary_Data'))
 OR (e.department = 'Engineering'  AND l.resource_type IN ('Financial_Report','Merger_Document'))
 OR (e.department = 'Sales'        AND l.resource_type IN ('HR_Database','Security_Config','Salary_Data'))
 OR (e.department = 'Operations'   AND l.resource_type IN ('HR_Database','Legal_Document','Salary_Data'))
GROUP BY l.employee_id, e.full_name, e.department, l.resource_type
ORDER BY avg_risk_score DESC;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 6: SECURITY FAILURE ANALYSIS                   │
-- └─────────────────────────────────────────────────────────┘

-- Q17: Repeated Authentication Failures
SELECT
    l.employee_id,
    e.full_name,
    e.department,
    COUNT(l.log_id)                                                 AS failed_attempts,
    COUNT(DISTINCT CAST(l.timestamp AS DATE))                      AS days_with_failures,
    COUNT(DISTINCT l.ip_address)                                   AS distinct_ips,
    COUNT(DISTINCT l.resource_type)                                AS resources_attempted,
    MAX(l.timestamp)                                               AS last_failure
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.access_failed = 1
GROUP BY l.employee_id, e.full_name, e.department
HAVING failed_attempts >= 3
ORDER BY failed_attempts DESC;


-- Q18: Brute-Force Pattern Detection (Many Fails in Short Window)
SELECT
    employee_id,
    DATE(timestamp)                                                 AS event_date,
    COUNT(*)                                                        AS fail_count,
    MIN(timestamp)                                                  AS window_start,
    MAX(timestamp)                                                  AS window_end,
    COUNT(DISTINCT ip_address)                                     AS distinct_ips,
    COUNT(DISTINCT resource_type)                                  AS distinct_resources
FROM access_logs_enriched
WHERE access_failed = 1
GROUP BY employee_id, DATE(timestamp)
HAVING fail_count >= 3
ORDER BY fail_count DESC;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 7: DEPARTMENT & TREND ANALYSIS                 │
-- └─────────────────────────────────────────────────────────┘

-- Q19: Department Risk Leaderboard
SELECT
    department,
    COUNT(DISTINCT employee_id)                                     AS employees,
    COUNT(log_id)                                                   AS total_events,
    ROUND(AVG(rule_score), 2)                                       AS avg_risk_score,
    SUM(CASE WHEN rule_score >= 60 THEN 1 ELSE 0 END)              AS high_risk_events,
    ROUND(SUM(download_size_mb), 2)                                AS total_downloads_mb,
    SUM(CASE WHEN is_after_hours = 1 THEN 1 ELSE 0 END)            AS after_hours_events,
    SUM(CASE WHEN location IN ('Foreign_IP','Proxy') THEN 1 ELSE 0 END) AS suspicious_location_events
FROM access_logs_enriched
GROUP BY department
ORDER BY avg_risk_score DESC;


-- Q20: Monthly Risk Escalation Trend
SELECT
    strftime('%Y-%m', timestamp)                                    AS month,
    COUNT(log_id)                                                   AS total_events,
    SUM(CASE WHEN rule_score >= 60 THEN 1 ELSE 0 END)              AS high_risk_events,
    ROUND(AVG(rule_score), 2)                                       AS avg_risk_score,
    ROUND(SUM(download_size_mb), 2)                                AS total_downloads_mb,
    COUNT(DISTINCT employee_id)                                     AS active_employees,
    SUM(CASE WHEN access_failed = 1 THEN 1 ELSE 0 END)             AS failed_attempts
FROM access_logs_enriched
GROUP BY strftime('%Y-%m', timestamp)
ORDER BY month;


-- Q21: Week-Over-Week Risk Change
WITH weekly AS (
    SELECT
        strftime('%Y-W%W', timestamp)                               AS week,
        ROUND(AVG(rule_score), 2)                                   AS avg_risk_score,
        COUNT(log_id)                                               AS total_events,
        SUM(CASE WHEN rule_score >= 60 THEN 1 ELSE 0 END)         AS high_risk_events
    FROM access_logs_enriched
    GROUP BY week
)
SELECT
    week,
    avg_risk_score,
    total_events,
    high_risk_events,
    ROUND(avg_risk_score - LAG(avg_risk_score) OVER (ORDER BY week), 2) AS risk_change_wow,
    ROUND((avg_risk_score - LAG(avg_risk_score) OVER (ORDER BY week))
          / LAG(avg_risk_score) OVER (ORDER BY week) * 100, 1)         AS risk_pct_change
FROM weekly;


-- ┌─────────────────────────────────────────────────────────┐
-- │  SECTION 8: INVESTIGATION SUPPORT QUERIES               │
-- └─────────────────────────────────────────────────────────┘

-- Q22: Full Audit Trail for Specific Employee
-- Replace 'EMP1075' with the employee under investigation
SELECT
    l.log_id,
    l.timestamp,
    l.resource_type,
    l.sensitivity_level,
    l.action,
    l.location,
    l.ip_address,
    l.device_type,
    l.download_size_mb,
    l.session_duration_min,
    l.access_failed,
    l.is_after_hours,
    l.is_weekend,
    l.rule_score,
    l.risk_level
FROM access_logs_enriched l
WHERE l.employee_id = 'EMP1075'
ORDER BY l.timestamp DESC;


-- Q23: Peer Comparison — Is Employee Outlier vs Peers?
WITH dept_stats AS (
    SELECT
        e.department,
        ROUND(AVG(r.total_download_mb), 2)   AS dept_avg_download,
        ROUND(AVG(r.after_hours_pct), 4)     AS dept_avg_after_hrs,
        ROUND(AVG(r.final_risk_score), 2)    AS dept_avg_risk
    FROM employee_risk_scores r
    JOIN employees e ON r.employee_id = e.employee_id
    GROUP BY e.department
)
SELECT
    e.employee_id,
    e.full_name,
    e.department,
    r.final_risk_score,
    r.total_download_mb,
    r.after_hours_pct,
    ds.dept_avg_risk,
    ds.dept_avg_download,
    ds.dept_avg_after_hrs,
    ROUND(r.final_risk_score / ds.dept_avg_risk, 2) AS risk_vs_dept_ratio
FROM employee_risk_scores r
JOIN employees e ON r.employee_id = e.employee_id
JOIN dept_stats ds ON ds.department = e.department
WHERE r.risk_level IN ('Critical','High')
ORDER BY risk_vs_dept_ratio DESC;


-- Q24: Suspicious Sequence — After-Hours + Confidential + Large Download
SELECT
    l.log_id,
    l.timestamp,
    l.employee_id,
    e.full_name,
    e.department,
    l.resource_type,
    l.action,
    l.location,
    ROUND(l.download_size_mb, 2)   AS download_mb,
    l.rule_score
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.is_after_hours = 1
  AND l.sensitivity_level IN ('Highly Confidential','Confidential')
  AND l.download_size_mb > 50
  AND l.action IN ('DOWNLOAD','COPY','SHARE')
ORDER BY l.rule_score DESC, l.download_size_mb DESC;


-- Q25: Delete Event Analysis (Data Destruction Indicator)
SELECT
    l.employee_id,
    e.full_name,
    e.department,
    COUNT(l.log_id)                                                 AS delete_count,
    COUNT(DISTINCT l.resource_type)                                AS resources_deleted,
    SUM(CASE WHEN l.sensitivity_level='Highly Confidential' THEN 1 ELSE 0 END) AS confidential_deletes,
    SUM(CASE WHEN l.is_after_hours = 1 THEN 1 ELSE 0 END)         AS after_hours_deletes,
    MAX(l.timestamp)                                               AS last_delete_event,
    ROUND(AVG(l.rule_score), 2)                                    AS avg_risk_score
FROM access_logs_enriched l
JOIN employees e ON l.employee_id = e.employee_id
WHERE l.action = 'DELETE'
GROUP BY l.employee_id, e.full_name, e.department
ORDER BY delete_count DESC, confidential_deletes DESC;

-- ============================================================
-- END OF SQL QUERY LIBRARY
-- Total: 25 production-ready queries
-- ============================================================
