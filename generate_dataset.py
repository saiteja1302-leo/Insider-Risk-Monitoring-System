import pandas as pd, numpy as np, random, os
from faker import Faker
from datetime import datetime

fake = Faker(); np.random.seed(42); random.seed(42)

NUM_EMPLOYEES=150; NUM_RECORDS=10_000
START_DATE=datetime(2024,1,1); END_DATE=datetime(2024,12,31)

DEPTS={"Finance":0.15,"Engineering":0.25,"HR":0.10,"Sales":0.20,"Legal":0.08,"Operations":0.12,"IT":0.10}
ROLES={"Finance":["Financial Analyst","Accountant","CFO","Controller","Auditor"],
       "Engineering":["Software Engineer","Senior Engineer","Tech Lead","DevOps","Architect"],
       "HR":["HR Manager","Recruiter","HR Director","Benefits Admin"],
       "Sales":["Sales Rep","Account Manager","Sales Director","SDR"],
       "Legal":["Legal Counsel","Paralegal","Compliance Officer","General Counsel"],
       "Operations":["Operations Manager","Analyst","Project Manager","Coordinator"],
       "IT":["IT Admin","Security Analyst","Network Engineer","Support Specialist"]}
RESOURCES=["Financial_Report","HR_Database","Source_Code","Customer_Data","Legal_Document",
           "Executive_Email","Product_Roadmap","Employee_Records","Security_Config",
           "Merger_Document","Salary_Data","IP_Document","General_File","Internal_Wiki","Meeting_Notes"]
SENS={"Financial_Report":"Confidential","HR_Database":"Highly Confidential","Source_Code":"Internal",
      "Customer_Data":"Confidential","Legal_Document":"Confidential","Executive_Email":"Highly Confidential",
      "Product_Roadmap":"Confidential","Employee_Records":"Highly Confidential","Security_Config":"Highly Confidential",
      "Merger_Document":"Highly Confidential","Salary_Data":"Highly Confidential","IP_Document":"Confidential",
      "General_File":"Public","Internal_Wiki":"Internal","Meeting_Notes":"Internal"}
ACTIONS=["VIEW","DOWNLOAD","EDIT","DELETE","SHARE","PRINT","COPY"]
AW=[0.40,0.25,0.15,0.05,0.07,0.04,0.04]
LOCS=["Office","Home","VPN","Unknown","Foreign_IP","Proxy"]
LW=[0.55,0.20,0.15,0.04,0.03,0.03]

# 24-element probability arrays for hours
PROBS_NORMAL = np.array([0.002]*7 + [0.08,0.11,0.12,0.11,0.09,0.07,0.10,0.11,0.09,0.07] + [0.015]*7); PROBS_NORMAL/=PROBS_NORMAL.sum()
PROBS_ATRISK = np.array([0.03]*7 + [0.04]*10 + [0.03]*7); PROBS_ATRISK/=PROBS_ATRISK.sum()

def gen_employees():
    rows=[]; eid=1000
    dl=list(DEPTS.keys()); dp=list(DEPTS.values())
    for _ in range(NUM_EMPLOYEES):
        dept=np.random.choice(dl,p=dp); role=random.choice(ROLES[dept])
        rp=np.random.choice(["normal","at_risk","malicious"],p=[0.87,0.10,0.03])
        rows.append({"employee_id":f"EMP{eid}","full_name":fake.name(),"email":fake.email(),
                     "department":dept,"role":role,
                     "hire_date":fake.date_between(start_date="-8y",end_date="-6m"),
                     "manager_id":None,
                     "employment_status":np.random.choice(["Active","On_Leave","Terminating"],p=[0.82,0.10,0.08]),
                     "risk_profile":rp})
        eid+=1
    df=pd.DataFrame(rows)
    for i,r in df.iterrows():
        same=df[(df.department==r.department)&(df.index!=i)]
        df.at[i,"manager_id"]=same.sample(1).employee_id.values[0] if len(same) else r.employee_id
    return df

def rand_ts(profile):
    d=fake.date_between(start_date=START_DATE,end_date=END_DATE)
    if profile=="malicious":
        h=random.choice(list(range(0,7))+list(range(20,24)))
    elif profile=="at_risk":
        h=int(np.random.choice(24,p=PROBS_ATRISK))
    else:
        h=int(np.random.choice(24,p=PROBS_NORMAL))
    return datetime.combine(d,datetime.min.time().replace(hour=h,minute=random.randint(0,59),second=random.randint(0,59)))

def gen_logs(emp_df):
    eids=emp_df.employee_id.tolist()
    prof=dict(zip(emp_df.employee_id,emp_df.risk_profile))
    w=np.array([3. if prof[e]=="malicious" else 1.5 if prof[e]=="at_risk" else 1. for e in eids])
    w/=w.sum(); rows=[]
    for i in range(NUM_RECORDS):
        eid=np.random.choice(eids,p=w); p=prof[eid]
        er=emp_df[emp_df.employee_id==eid].iloc[0]; ts=rand_ts(p)
        if p=="malicious":
            res=np.random.choice(["Financial_Report","HR_Database","Merger_Document","Employee_Records","Salary_Data","Customer_Data","IP_Document","Security_Config"],p=[0.15,0.15,0.15,0.10,0.15,0.10,0.10,0.10])
            act=np.random.choice(["DOWNLOAD","COPY","SHARE","VIEW"],p=[0.45,0.25,0.20,0.10])
            loc=np.random.choice(["Foreign_IP","Proxy","Unknown","Home"],p=[0.35,0.30,0.20,0.15])
        else:
            res=random.choice(RESOURCES); act=np.random.choice(ACTIONS,p=AW); loc=np.random.choice(LOCS,p=LW)
        dl=round(random.expovariate(1/((5 if p=="malicious" else 1)*20)),2) if act in("DOWNLOAD","COPY","SHARE") else 0.0
        rows.append({"log_id":f"LOG{1000000+i}","employee_id":eid,"department":er.department,
                     "timestamp":ts,"date":ts.date(),"hour":ts.hour,"day_of_week":ts.strftime("%A"),
                     "is_weekend":ts.weekday()>=5,"is_after_hours":not(9<=ts.hour<18),
                     "resource_type":res,"sensitivity_level":SENS[res],"action":act,"location":loc,
                     "download_size_mb":dl,"session_duration_min":max(1,int(np.random.normal(45 if p=="normal" else 15,30))),
                     "access_failed":np.random.choice([True,False],p=[0.20 if p=="malicious" else 0.05,0.80 if p=="malicious" else 0.95]),
                     "ip_address":fake.ipv4(),
                     "device_type":np.random.choice(["Laptop","Desktop","Mobile","Unknown"],p=[0.50,0.30,0.15,0.05]),
                     "vpn_used":loc=="VPN","_rp":p})
    return pd.DataFrame(rows)

print("Generating employees...")
emp=gen_employees()
print("Generating logs...")
log=gen_logs(emp)
out="/home/claude/insider-risk-system/data"; os.makedirs(out,exist_ok=True)
emp.drop(columns=["risk_profile"]).to_csv(f"{out}/employees.csv",index=False)
log.drop(columns=["_rp"]).to_csv(f"{out}/access_logs.csv",index=False)
print(f"employees.csv -> {len(emp):,} rows")
print(f"access_logs.csv -> {len(log):,} rows")
