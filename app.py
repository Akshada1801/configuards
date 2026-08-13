from detection.detector_engine import run_scan
from remediation.remediation_engine import process_remediation

import json
import os
import random
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from datetime import datetime

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from flask import Flask, render_template, request, redirect, url_for, session, jsonify


app = Flask(__name__)
app.secret_key = os.urandom(24)


# ============================================================
# USERS
# ============================================================

def load_users():
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_users():
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)


users = load_users()


# ============================================================
# FINDINGS
# ============================================================

def get_findings_stats():
    """Read real findings from security_findings.json and calculate stats."""
    try:
        with open("security_findings.json", "r") as f:
            findings = json.load(f)
    except Exception:
        findings = []

    stats = {
        "total": len(findings),
        "high": 0,
        "medium": 0,
        "low": 0,
        "resolved": 0,
        "compliance": 100
    }

    for issue in findings:
        severity = issue.get("severity", "").lower()
        status = issue.get("status", "").upper()

        if severity == "high":
            stats["high"] += 1
        elif severity == "medium":
            stats["medium"] += 1
        elif severity == "low":
            stats["low"] += 1

        if status in ["RESOLVED", "JUST RESOLVED"]:
            stats["resolved"] += 1

    open_issues = stats["total"] - stats["resolved"]
    stats["compliance"] = max(0, 100 - (open_issues * 5))

    return stats, findings


def load_findings():
    try:
        with open("security_findings.json", "r") as f:
            return json.load(f)
    except Exception:
        return []


# ============================================================
# VALIDATION
# ============================================================

def validate_email(email):
    """Basic email format validation."""
    email = email.strip().lower()
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.fullmatch(pattern, email) is not None


def normalize_mobile(mobile):
    """
    Accept:
      9876543210
      +919876543210
      +91 98765 43210
      091234567890

    Return normalized 10-digit Indian mobile number or None.
    """
    digits = re.sub(r"\D", "", mobile)

    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    elif digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]

    if len(digits) != 10:
        return None

    if digits[0] not in "6789":
        return None

    return digits


def validate_aws_credentials(access_key, secret_key, region):
    """
    Real AWS verification using STS GetCallerIdentity.
    No resources are changed by this check.
    """
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

        identity = sts.get_caller_identity()

        return True, {
            "account": identity["Account"],
            "arn": identity["Arn"]
        }

    except Exception as e:
        return False, str(e)


# ============================================================
# FREE EMAIL OTP
# ============================================================

def generate_email_otp():
    return f"{random.randint(0, 999999):06d}"


def send_email_otp(email, otp):
    """
    Send OTP through SMTP.

    Configure these environment variables on the computer running Flask:
      CONFIGUARDS_SMTP_HOST
      CONFIGUARDS_SMTP_PORT
      CONFIGUARDS_SMTP_USER
      CONFIGUARDS_SMTP_PASSWORD
      CONFIGUARDS_SMTP_FROM

    For Gmail, use an App Password, not the normal Gmail password.
    """
    smtp_host = os.getenv("CONFIGUARDS_SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("CONFIGUARDS_SMTP_PORT", "587"))
    smtp_user = os.getenv("CONFIGUARDS_SMTP_USER")
    smtp_password = os.getenv("CONFIGUARDS_SMTP_PASSWORD")
    smtp_from = os.getenv("CONFIGUARDS_SMTP_FROM", smtp_user or "")

    if not smtp_user or not smtp_password:
        return False, (
            "Email OTP is not configured. Set "
            "CONFIGUARDS_SMTP_USER and CONFIGUARDS_SMTP_PASSWORD."
        )

    message = EmailMessage()
    message["Subject"] = "Configuards Email Verification OTP"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(
        f"""Hello,

Your Configuards email verification OTP is:

{otp}

This OTP expires in 10 minutes.

If you did not request this verification, you can ignore this email.

Configuards
Cloud Security Posture Management
"""
    )

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_password)
            server.send_message(message)

        return True, "OTP sent successfully."

    except Exception as e:
        return False, str(e)


# ============================================================
# AWS SECURITY SCANNER CLASS
# ============================================================

class AWSSecurityScanner:
    def __init__(
        self,
        aws_access_key=None,
        aws_secret_key=None,
        region="us-east-1"
    ):
        self.region = region

        try:
            if aws_access_key and aws_secret_key:
                self.s3 = boto3.client(
                    "s3",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                self.ec2 = boto3.client(
                    "ec2",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
                self.iam = boto3.client(
                    "iam",
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=region
                )
            else:
                self.s3 = boto3.client("s3", region_name=region)
                self.ec2 = boto3.client("ec2", region_name=region)
                self.iam = boto3.client("iam", region_name=region)

            self.connected = True

        except Exception:
            self.connected = False

    def scan_s3_buckets(self):
        findings = []

        try:
            buckets = self.s3.list_buckets()["Buckets"]

            for bucket in buckets:
                bucket_name = bucket["Name"]

                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)

                    for grant in acl["Grants"]:
                        if (
                            grant["Grantee"].get("URI")
                            == "http://acs.amazonaws.com/groups/global/AllUsers"
                        ):
                            findings.append({
                                "id": f"s3-{bucket_name}",
                                "resource": "S3 Bucket",
                                "name": bucket_name,
                                "issue": (
                                    "Public access enabled - "
                                    "Bucket is accessible to everyone"
                                ),
                                "severity": "high",
                                "status": "Open",
                                "fix_available": True,
                                "risk": (
                                    "Data leakage, unauthorized access"
                                )
                            })

                except Exception:
                    pass

        except Exception:
            pass

        return findings

    def scan_security_groups(self):
        findings = []

        try:
            sgs = self.ec2.describe_security_groups()["SecurityGroups"]

            for sg in sgs:
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            port = rule.get("FromPort", "All")

                            findings.append({
                                "id": f'sg-{sg["GroupId"]}',
                                "resource": "Security Group",
                                "name": sg["GroupName"],
                                "issue": (
                                    f"Port {port} open to internet "
                                    "(0.0.0.0/0)"
                                ),
                                "severity": (
                                    "high"
                                    if port in [22, 3389, 3306, 5432]
                                    else "medium"
                                ),
                                "status": "Open",
                                "fix_available": True,
                                "risk": (
                                    "Unauthorized access, potential breach"
                                )
                            })

        except Exception:
            pass

        return findings

    def scan_ec2_instances(self):
        findings = []

        try:
            instances = self.ec2.describe_instances()

            for reservation in instances["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance["State"]["Name"] == "running":
                        for vol in instance.get("BlockDeviceMappings", []):
                            if not vol.get("Ebs", {}).get(
                                "Encrypted", False
                            ):
                                findings.append({
                                    "id": (
                                        f'ec2-{instance["InstanceId"]}'
                                    ),
                                    "resource": "EC2 Instance",
                                    "name": instance["InstanceId"],
                                    "issue": (
                                        "Unencrypted EBS volume attached"
                                    ),
                                    "severity": "medium",
                                    "status": "Open",
                                    "fix_available": False,
                                    "risk": (
                                        "Data exposure if volume "
                                        "is compromised"
                                    )
                                })

        except Exception:
            pass

        return findings

    def fix_s3_public_access(self, bucket_name):
        try:
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                }
            )

            return True, "Public access blocked successfully"

        except Exception as e:
            return False, str(e)

    def fix_security_group(self, group_id, port):
        try:
            self.ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0"}
                    ]
                }]
            )

            return (
                True,
                f"Port {port} access from 0.0.0.0/0 removed"
            )

        except Exception as e:
            return False, str(e)


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    # --------------------------------------------------------
    # STEP 2: Verify email OTP
    # --------------------------------------------------------
    if request.method == "POST" and request.form.get("action") == "verify_email":
        email = request.form.get("email", "").strip().lower()
        entered_otp = request.form.get("email_otp", "").strip()

        if not validate_email(email):
            return render_template(
                "signup.html",
                error="Please enter a valid email address.",
                email=email
            )

        if email in users:
            return render_template(
                "signup.html",
                error="Email already exists.",
                email=email
            )

        stored_email = session.get("signup_email")
        stored_otp = session.get("signup_email_otp")
        otp_time = session.get("signup_email_otp_time", 0)

        if stored_email != email or not stored_otp:
            return render_template(
                "signup.html",
                error="Please request a new email OTP.",
                email=email
            )

        if time.time() - otp_time > 600:
            session.pop("signup_email_otp", None)
            session.pop("signup_email_otp_time", None)

            return render_template(
                "signup.html",
                error="OTP expired. Please request a new OTP.",
                email=email
            )

        if entered_otp != stored_otp:
            return render_template(
                "signup.html",
                error="Invalid email OTP.",
                email=email
            )

        session["signup_email_verified"] = True
        session.pop("signup_email_otp", None)
        session.pop("signup_email_otp_time", None)

        return render_template(
            "signup.html",
            success="Email verified successfully.",
            email=email,
            email_verified=True
        )

    # --------------------------------------------------------
    # STEP 1: Send email OTP
    # --------------------------------------------------------
    if request.method == "POST" and request.form.get("action") == "send_email_otp":
        email = request.form.get("email", "").strip().lower()

        if not validate_email(email):
            return render_template(
                "signup.html",
                error="Please enter a valid email address.",
                email=email
            )

        if email in users:
            return render_template(
                "signup.html",
                error="Email already exists.",
                email=email
            )

        otp = generate_email_otp()

        sent, message = send_email_otp(email, otp)

        if not sent:
            return render_template(
                "signup.html",
                error=f"Could not send email OTP: {message}",
                email=email
            )

        session["signup_email"] = email
        session["signup_email_otp"] = otp
        session["signup_email_otp_time"] = time.time()
        session["signup_email_verified"] = False

        return render_template(
            "signup.html",
            success="OTP sent to your email. Enter it to verify.",
            email=email,
            otp_sent=True
        )

    # --------------------------------------------------------
    # STEP 3: Complete signup
    # --------------------------------------------------------
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        mobile_raw = request.form.get("mobile", "").strip()
        email = request.form.get("email", "").strip().lower()

        aws_access_key = request.form.get(
            "aws_access_key", ""
        ).strip()
        aws_secret_key = request.form.get(
            "aws_secret_key", ""
        ).strip()
        aws_region = request.form.get(
            "aws_region", "us-east-1"
        ).strip()

        password = request.form.get("password", "")
        confirm_password = request.form.get(
            "confirm_password", ""
        )

        # Email format
        if not validate_email(email):
            return render_template(
                "signup.html",
                error="Please enter a valid email address.",
                email=email
            )

        # Email ownership verification
        if (
            not session.get("signup_email_verified")
            or session.get("signup_email") != email
        ):
            return render_template(
                "signup.html",
                error="Please verify your email with the OTP first.",
                email=email
            )

        # Phone format validation only. No SMS is sent.
        mobile = normalize_mobile(mobile_raw)

        if not mobile:
            return render_template(
                "signup.html",
                error=(
                    "Please enter a valid Indian mobile number "
                    "starting with 6, 7, 8 or 9."
                ),
                email=email
            )

        if email in users:
            return render_template(
                "signup.html",
                error="Email already exists.",
                email=email
            )

        if password != confirm_password:
            return render_template(
                "signup.html",
                error="Passwords do not match.",
                email=email
            )

        if len(password) < 8:
            return render_template(
                "signup.html",
                error="Password must be at least 8 characters.",
                email=email
            )

        # Real AWS credential verification
        valid, result = validate_aws_credentials(
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if not valid:
            return render_template(
                "signup.html",
                error=(
                    "Invalid AWS Credentials. Please check "
                    "Access Key, Secret Key and Region."
                ),
                email=email,
                email_verified=True
            )

        # Save only after email, phone and AWS validation pass.
        users[email] = {
            "fullname": fullname,
            "mobile": mobile,
            "email_verified": True,
            "phone_format_verified": True,

            "aws_access_key": aws_access_key,
            "aws_secret_key": aws_secret_key,
            "aws_region": aws_region,

            "aws_account": result["account"],
            "aws_arn": result["arn"],
            "aws_connected": True,

            "password": password
        }

        save_users()

        # Clean temporary signup verification data.
        session.pop("signup_email", None)
        session.pop("signup_email_otp", None)
        session.pop("signup_email_otp_time", None)
        session.pop("signup_email_verified", None)

        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["username"].strip().lower()
        password = request.form["password"]

        if email not in users:
            return render_template(
                "login.html",
                error="Invalid Email or Password"
            )

        if users[email]["password"] != password:
            return render_template(
                "login.html",
                error="Invalid Email or Password"
            )

        access_key = users[email]["aws_access_key"]
        secret_key = users[email]["aws_secret_key"]
        region = users[email]["aws_region"]

        valid, result = validate_aws_credentials(
            access_key,
            secret_key,
            region
        )

        if valid:
            users[email]["aws_connected"] = True
            users[email]["aws_account"] = result["account"]
            users[email]["aws_arn"] = result["arn"]
        else:
            users[email]["aws_connected"] = False

        save_users()

        session["user"] = users[email]["fullname"]

        session["aws_access_key"] = access_key
        session["aws_secret_key"] = secret_key
        session["aws_region"] = region
        session["aws_connected"] = users[email]["aws_connected"]

        session["user_info"] = {
            "fullname": users[email]["fullname"],
            "email": email,
            "mobile": users[email]["mobile"],
            "aws_region": region,
            "aws_connected": users[email]["aws_connected"],
            "aws_account": users[email].get("aws_account", ""),
            "aws_arn": users[email].get("aws_arn", "")
        }

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    stats, all_findings = get_findings_stats()

    open_findings = [
        f for f in all_findings
        if f.get("status", "").upper()
        not in ["RESOLVED", "JUST RESOLVED"]
    ]

    findings = (
        open_findings[-8:]
        if len(open_findings) > 8
        else open_findings
    )

    open_count = len(open_findings)

    recent_activity = [
        {
            "text": "Security scan completed",
            "time": datetime.now().strftime("%H:%M")
        },
        {
            "text": f"Found {open_count} open security findings",
            "time": datetime.now().strftime("%H:%M")
        },
        {
            "text": f"{stats['resolved']} issues resolved",
            "time": datetime.now().strftime("%H:%M")
        }
    ]

    return render_template(
        "dashboard.html",
        user=session["user"],
        findings=findings,
        stats=stats,
        recent_activity=recent_activity
    )


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        email = session["user_info"]["email"]

        users[email]["fullname"] = request.form["fullname"]
        users[email]["mobile"] = request.form["mobile"]
        users[email]["aws_builder_id"] = request.form["aws_builder_id"]

        save_users()

        session["user"] = users[email]["fullname"]
        session["user_info"]["fullname"] = users[email]["fullname"]
        session["user_info"]["mobile"] = users[email]["mobile"]
        session["user_info"]["aws_builder_id"] = (
            users[email]["aws_builder_id"]
        )

    user_info = session.get("user_info", {})
    aws_configured = True

    return render_template(
        "profile.html",
        user=session["user"],
        user_info=user_info,
        aws_configured=aws_configured
    )


@app.route("/findings")
def findings():
    if "user" not in session:
        return redirect(url_for("login"))

    findings = load_findings()

    return render_template(
        "findings.html",
        user=session["user"],
        findings=findings
    )


@app.route("/scan", methods=["POST"])
def scan():
    if "user" not in session:
        return jsonify({
            "success": False,
            "message": "Not logged in"
        })

    try:
        aws_access_key = session.get("aws_access_key")
        aws_secret_key = session.get("aws_secret_key")
        aws_region = session.get("aws_region", "us-east-1")

        if not aws_access_key or not aws_secret_key:
            return jsonify({
                "success": False,
                "message": "AWS credentials are not available in the session."
            })

        run_scan(
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        return jsonify({
            "success": True,
            "message": "AWS scan completed successfully"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


@app.route("/clear-resolved", methods=["POST"])
def clear_resolved():
    if "user" not in session:
        return jsonify({
            "success": False,
            "message": "Not logged in"
        })

    try:
        findings = load_findings()

        open_findings = [
            f for f in findings
            if f.get("status", "").upper() == "OPEN"
        ]

        with open("security_findings.json", "w") as f:
            json.dump(open_findings, f, indent=4)

        removed_count = len(findings) - len(open_findings)

        return jsonify({
            "success": True,
            "message": (
                f"Removed {removed_count} resolved findings"
            )
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


@app.route("/remediate", methods=["POST"])
def remediate():
    if "user" not in session:
        return jsonify({
            "success": False,
            "message": "Not logged in"
        })

    data = request.json or {}

    resource_type = data.get("resource_type")
    resource_name = data.get("resource_name")
    issue = data.get("issue")

    try:
        # IMPORTANT:
        # Manual remediation also uses the currently logged-in user's
        # AWS credentials.
        result = process_remediation(
            resource_type,
            resource_name,
            issue,
            session.get("aws_access_key"),
            session.get("aws_secret_key"),
            session.get("aws_region", "us-east-1")
        )

        if result.get("success"):
            findings = load_findings()

            for finding in findings:
                if (
                    finding.get("name") == resource_name
                    and finding.get("resource") == resource_type
                    and finding.get("issue") == issue
                ):
                    finding["status"] = "JUST RESOLVED"
                    finding["resolved_at"] = (
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                    finding["timestamp"] = (
                        datetime.now().strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )

            with open("security_findings.json", "w") as f:
                json.dump(findings, f, indent=4)

            return jsonify({
                "success": True,
                "message": result.get(
                    "message",
                    "Issue resolved successfully"
                )
            })

        return jsonify({
            "success": False,
            "message": result.get(
                "message",
                "Remediation failed"
            )
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        })


@app.route("/reports")
def reports():
    if "user" not in session:
        return redirect(url_for("login"))

    stats, findings = get_findings_stats()

    stats["scanned"] = stats["total"]
    stats["resources"] = stats["total"]

    return render_template(
        "reports.html",
        user=session["user"],
        stats=stats,
        current_date=datetime.now().strftime("%B %d, %Y")
    )


@app.route("/download-report/<report_type>")
def download_report(report_type):
    if "user" not in session:
        return redirect(url_for("login"))

    from flask import make_response

    findings = load_findings()
    stats, _ = get_findings_stats()

    report_content = f"""CONFIGUARDS SECURITY REPORT
{'=' * 60}
Report Type: {report_type.replace('-', ' ').title()}
Generated: {datetime.now().strftime('%B %d, %Y %H:%M:%S')}
User: {session['user']}
{'=' * 60}

SUMMARY
{'-' * 60}
Total Findings: {stats['total']}
High Severity: {stats['high']}
Medium Severity: {stats['medium']}
Low Severity: {stats['low']}
Resolved: {stats['resolved']}
Compliance Score: {stats['compliance']}%

DETAILED FINDINGS
{'-' * 60}
"""

    for i, finding in enumerate(findings, 1):
        report_content += f"""
{i}. {finding.get('resource', 'Unknown')} - {finding.get('name', 'N/A')}
   Issue: {finding.get('issue', 'No description')}
   Severity: {finding.get('severity', 'unknown').upper()}
   Status: {finding.get('status', 'Open')}
   Timestamp: {finding.get('timestamp', 'N/A')}
{'-' * 60}
"""

    if not findings:
        report_content += "\nNo security findings detected.\n"

    report_content += (
        "\n\nEnd of Report\n"
        "Generated by Configuards - Cloud Security Monitoring System\n"
    )

    response = make_response(report_content)
    response.headers["Content-Type"] = "text/plain"
    response.headers["Content-Disposition"] = (
        "attachment; "
        f"filename=configuards_{report_type}_"
        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )

    return response


@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "settings.html",
        user=session["user"]
    )


@app.route("/about")
def about():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "about.html",
        user=session["user"]
    )


@app.route("/feedback")
def feedback():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template(
        "about.html",
        user=session["user"]
    )


@app.route("/change-password")
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/two-factor")
def two_factor():
    if "user" not in session:
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)