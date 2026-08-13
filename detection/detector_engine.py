import json
import sys
import os
from datetime import datetime

# Allow project root imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection.s3_detector import scan_s3
from detection.ec2_detector import scan_ec2
from detection.iam_detector import scan_iam
from detection.sg_detector import scan_security_groups


FINDINGS_FILE = "security_findings.json"


def run_scan(aws_access_key=None, aws_secret_key=None, aws_region="us-east-1"):
    """
    Run all AWS security scans using the logged-in user's AWS credentials.

    The credentials are passed from the Flask login/session flow into each
    detector and then into the remediation engine. If credentials are None,
    boto3 may fall back to its normal credential chain.
    """
    findings = []

    print("Starting AWS Security Scan...\n")

    # Run each detector with the logged-in user's credentials.
    try:
        findings += scan_s3(
            aws_access_key,
            aws_secret_key,
            aws_region
        )
    except Exception as e:
        print("S3 scan error:", e)

    try:
        findings += scan_ec2(
            aws_access_key,
            aws_secret_key,
            aws_region
        )
    except Exception as e:
        print("EC2 scan error:", e)

    try:
        findings += scan_iam(
            aws_access_key,
            aws_secret_key,
            aws_region
        )
    except Exception as e:
        print("IAM scan error:", e)

    try:
        findings += scan_security_groups(
            aws_access_key,
            aws_secret_key,
            aws_region
        )
    except Exception as e:
        print("Security Group scan error:", e)

    print("\nScan Completed")

    # Load existing findings.
    try:
        with open(FINDINGS_FILE, "r") as f:
            existing_findings = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_findings = []

    # Keep historical resolved findings.
    resolved_findings = [
        finding
        for finding in existing_findings
        if finding.get("status") in ["RESOLVED", "JUST RESOLVED"]
    ]

    # Save current findings together with historical resolved findings.
    all_findings = resolved_findings + findings

    with open(FINDINGS_FILE, "w") as f:
        json.dump(all_findings, f, indent=4)

    # ------------------------------------------------------------
    # HIGH severity = automatic remediation
    # ------------------------------------------------------------
    print("\n[ALERT] Checking for HIGH severity issues...")
    high_severity_count = 0

    from remediation.remediation_engine import process_remediation

    for issue in findings:
        if issue.get("severity", "").upper() != "HIGH":
            continue

        high_severity_count += 1

        print(f"   [AUTO-FIX] HIGH SEVERITY: {issue.get('name')}")
        print(f"   Resource: {issue.get('resource')}")
        print(f"   Issue: {issue.get('issue')}")

        # IMPORTANT:
        # Pass the credentials belonging to the currently logged-in user.
        result = process_remediation(
            issue.get("resource"),
            issue.get("name"),
            issue.get("issue"),
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result.get("success"):
            print(f"   [FIXED] {result.get('message')}")

            issue["status"] = "JUST RESOLVED"
            issue["resolved_at"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        else:
            print(f"   [FAILED] {result.get('message')}")

    # Save again after HIGH-severity remediation.
    all_findings = resolved_findings + findings

    with open(FINDINGS_FILE, "w") as f:
        json.dump(all_findings, f, indent=4)

    if high_severity_count > 0:
        print(f"\n[AUTO-REMEDIATION] Attempted for {high_severity_count} HIGH severity issue(s)")
    else:
        print("\n✅ No HIGH severity issues found")

    # Move JUST RESOLVED -> RESOLVED after one hour.
    from remediation.remediation_engine import (
        update_just_resolved_to_resolved
    )

    updated = update_just_resolved_to_resolved(hours=1)

    if updated > 0:
        print(
            f"[UPDATED] {updated} findings from "
            f"JUST RESOLVED to RESOLVED"
        )

    for issue in findings:
        print(str(issue).encode("ascii", "replace").decode("ascii"))

    return findings


if __name__ == "__main__":
    run_scan()