import json
from datetime import datetime
import os

LOG_FILE = "security_findings.json"

def log_finding(resource, name, issue, severity):

    finding = {
        "resource": resource,
        "name": name,
        "issue": issue,
        "severity": severity,
        "status": "OPEN",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

    with open(LOG_FILE, "r") as f:
        data = json.load(f)

    data.append(finding)

    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print("Logged finding:", finding)