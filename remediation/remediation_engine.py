import json
import boto3
import time
from datetime import datetime

FINDINGS_FILE = "security_findings.json"


def get_boto3_client(service, aws_access_key, aws_secret_key, aws_region):
    """
    Create a boto3 client using the credentials supplied by the logged-in user.

    If credentials are None, boto3's normal credential provider chain can
    still be used. In the Configuards web flow, valid credentials should be
    supplied from the user's login/session.
    """
    return boto3.client(
        service,
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )


def load_findings():
    try:
        with open(FINDINGS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def save_findings(findings):
    """Save findings to the JSON file."""
    with open(FINDINGS_FILE, "w") as f:
        json.dump(findings, f, indent=4)


def remediate_s3(
    bucket_name,
    issue,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Remediate S3 bucket issues based on issue type."""
    try:
        s3 = get_boto3_client(
            "s3",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if (
            "publicly accessible" in issue.lower()
            or "public access" in issue.lower()
        ):
            print(f"Blocking public access on S3 Bucket: {bucket_name}")

            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                }
            )

            print("S3 public access blocked.")

            return {
                "success": True,
                "message": "S3 bucket public access blocked successfully"
            }

        elif "missing tags" in issue.lower():
            return remediate_s3_tags(
                bucket_name,
                aws_access_key,
                aws_secret_key,
                aws_region
            )

        return {
            "success": False,
            "message": "Unknown S3 issue type"
        }

    except Exception as e:
        print(f"Error remediating S3 bucket: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_s3_tags(
    bucket_name,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Add default tags to an S3 bucket."""
    try:
        s3 = get_boto3_client(
            "s3",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print(f"Adding tags to S3 Bucket: {bucket_name}")

        s3.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={
                "TagSet": [
                    {"Key": "Environment", "Value": "Production"},
                    {"Key": "Owner", "Value": "SecurityTeam"},
                    {"Key": "Project", "Value": "Configuards"},
                    {"Key": "AutoTagged", "Value": "true"}
                ]
            }
        )

        print("S3 bucket tags added.")

        return {
            "success": True,
            "message": "S3 bucket tags added successfully"
        }

    except Exception as e:
        print(f"Error adding S3 tags: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_security_group(
    group_id,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Remove 0.0.0.0/0 ingress rules from a security group."""
    try:
        ec2 = get_boto3_client(
            "ec2",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print(f"Remediating Security Group: {group_id}")

        response = ec2.describe_security_groups(
            GroupIds=[group_id]
        )

        security_group = response["SecurityGroups"][0]

        for rule in security_group.get("IpPermissions", []):
            public_ranges = [
                ip_range
                for ip_range in rule.get("IpRanges", [])
                if ip_range.get("CidrIp") == "0.0.0.0/0"
            ]

            if not public_ranges:
                continue

            # Revoke only the public IPv4 ranges from this rule.
            revoke_permission = dict(rule)
            revoke_permission["IpRanges"] = public_ranges

            ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[revoke_permission]
            )

        print("Security group access removed.")

        return {
            "success": True,
            "message": "Security group rules removed successfully"
        }

    except Exception as e:
        print(f"Error remediating security group: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_ec2_public_ip(
    instance_id,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """
    Review an EC2 instance with a public IP.

    A public IP cannot simply be removed from a running instance through
    this function, so the instance is marked as reviewed.
    """
    try:
        ec2 = get_boto3_client(
            "ec2",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print(
            f"Adding security measures for EC2 Instance: "
            f"{instance_id}"
        )

        response = ec2.describe_instances(
            InstanceIds=[instance_id]
        )

        instance = response["Reservations"][0]["Instances"][0]

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "SecurityReview", "Value": "Completed"},
                {"Key": "PublicIPReviewed", "Value": "true"},
                {
                    "Key": "ReviewDate",
                    "Value": datetime.now().strftime("%Y-%m-%d")
                }
            ]
        )

        print("EC2 instance marked as reviewed.")

        return {
            "success": True,
            "message": (
                "EC2 instance marked as security reviewed "
                "(public IP cannot be removed from a running instance)"
            )
        }

    except Exception as e:
        print(f"Error reviewing EC2 instance: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_ec2_tags(
    instance_id,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Add default tags to an EC2 instance."""
    try:
        ec2 = get_boto3_client(
            "ec2",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print(f"Adding tags to EC2 Instance: {instance_id}")

        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "Environment", "Value": "Production"},
                {"Key": "Owner", "Value": "SecurityTeam"},
                {"Key": "Project", "Value": "Configuards"},
                {"Key": "AutoTagged", "Value": "true"}
            ]
        )

        print("EC2 instance tags added.")

        return {
            "success": True,
            "message": "EC2 instance tags added successfully"
        }

    except Exception as e:
        print(f"Error adding EC2 tags: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_iam_user(
    username,
    issue,
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Remediate supported IAM user issues."""
    try:
        iam = get_boto3_client(
            "iam",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print(f"Remediating IAM User: {username}")

        if "AdministratorAccess" in issue:
            iam.detach_user_policy(
                UserName=username,
                PolicyArn=(
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                )
            )

            iam.attach_user_policy(
                UserName=username,
                PolicyArn=(
                    "arn:aws:iam::aws:policy/ReadOnlyAccess"
                )
            )

            return {
                "success": True,
                "message": (
                    "Removed AdministratorAccess, "
                    "added ReadOnlyAccess"
                )
            }

        elif "old access key" in issue.lower():
            keys = iam.list_access_keys(
                UserName=username
            )["AccessKeyMetadata"]

            for key in keys:
                iam.delete_access_key(
                    UserName=username,
                    AccessKeyId=key["AccessKeyId"]
                )

            return {
                "success": True,
                "message": "Old access keys deleted"
            }

        elif "inactive" in issue.lower():
            iam.tag_user(
                UserName=username,
                Tags=[
                    {
                        "Key": "InactivityReviewed",
                        "Value": "true"
                    },
                    {
                        "Key": "ReviewDate",
                        "Value": datetime.now().strftime("%Y-%m-%d")
                    }
                ]
            )

            return {
                "success": True,
                "message": "User marked as reviewed for inactivity"
            }

        return {
            "success": False,
            "message": "Unknown IAM issue type"
        }

    except Exception as e:
        print(f"Error remediating IAM user: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def remediate_cloudtrail(
    aws_access_key,
    aws_secret_key,
    aws_region
):
    """Enable CloudTrail logging."""
    try:
        cloudtrail = get_boto3_client(
            "cloudtrail",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        s3 = get_boto3_client(
            "s3",
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        print("Enabling CloudTrail logging")

        bucket_name = (
            f"configuards-cloudtrail-{int(time.time())}"
        )

        # S3 bucket creation requires LocationConstraint for regions other
        # than us-east-1.
        if aws_region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={
                    "LocationConstraint": aws_region
                }
            )

        cloudtrail.create_trail(
            Name="configuards-security-trail",
            S3BucketName=bucket_name,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True
        )

        cloudtrail.start_logging(
            Name="configuards-security-trail"
        )

        print("CloudTrail enabled.")

        return {
            "success": True,
            "message": "CloudTrail logging enabled successfully"
        }

    except Exception as e:
        print(f"Error enabling CloudTrail: {e}")
        return {
            "success": False,
            "message": str(e)
        }


def update_status(resource_name):
    """Update a finding to JUST RESOLVED with a timestamp."""
    try:
        findings = load_findings()

        for finding in findings:
            if finding.get("name") == resource_name:
                finding["status"] = "JUST RESOLVED"
                finding["resolved_at"] = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        save_findings(findings)
        return True

    except Exception as e:
        print(f"Error updating status: {e}")
        return False


def update_just_resolved_to_resolved(hours=1):
    """Change JUST RESOLVED to RESOLVED after the specified time."""
    try:
        findings = load_findings()
        current_time = datetime.now()
        updated_count = 0

        for finding in findings:
            if (
                finding.get("status") == "JUST RESOLVED"
                and finding.get("resolved_at")
            ):
                resolved_time = datetime.strptime(
                    finding["resolved_at"],
                    "%Y-%m-%d %H:%M:%S"
                )

                hours_since_resolved = (
                    current_time - resolved_time
                ).total_seconds() / 3600

                if hours_since_resolved >= hours:
                    finding["status"] = "RESOLVED"
                    updated_count += 1

                    print(
                        f"Updated {finding['name']} from "
                        "JUST RESOLVED to RESOLVED"
                    )

        if updated_count > 0:
            save_findings(findings)
            print(
                f"\n✅ Updated {updated_count} findings from "
                "JUST RESOLVED to RESOLVED"
            )

        return updated_count

    except Exception as e:
        print(f"Error updating statuses: {e}")
        return 0


def cleanup_old_resolved_findings(hours=24):
    """Remove RESOLVED findings older than the specified time."""
    try:
        findings = load_findings()
        current_time = datetime.now()
        cleaned_findings = []
        removed_count = 0

        for finding in findings:
            if (
                finding.get("status") == "RESOLVED"
                and finding.get("resolved_at")
            ):
                resolved_time = datetime.strptime(
                    finding["resolved_at"],
                    "%Y-%m-%d %H:%M:%S"
                )

                hours_since_resolved = (
                    current_time - resolved_time
                ).total_seconds() / 3600

                if hours_since_resolved < hours:
                    cleaned_findings.append(finding)
                else:
                    removed_count += 1
                    print(
                        f"Removing old resolved finding: "
                        f"{finding['name']}"
                    )
            else:
                cleaned_findings.append(finding)

        if removed_count > 0:
            save_findings(cleaned_findings)
            print(
                f"\n🧹 Cleaned up {removed_count} "
                "old resolved findings"
            )

        return removed_count

    except Exception as e:
        print(f"Error cleaning up findings: {e}")
        return 0


def process_remediation(
    resource_type,
    resource_name,
    issue,
    aws_access_key=None,
    aws_secret_key=None,
    aws_region="us-east-1"
):
    """
    Process remediation using the logged-in user's AWS credentials.

    The credentials are optional for backward compatibility with older
    direct calls. The web application should pass the current user's
    credentials.
    """
    print(
        f"Processing remediation for "
        f"{resource_type}: {resource_name}"
    )
    print(f"Issue: {issue}")

    if resource_type == "Security Group":
        result = remediate_security_group(
            resource_name,
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result["success"]:
            update_status(resource_name)

        return result

    elif resource_type == "S3":
        result = remediate_s3(
            resource_name,
            issue,
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result["success"]:
            update_status(resource_name)

        return result

    elif resource_type == "EC2 Instance":
        if "public ip" in issue.lower():
            result = remediate_ec2_public_ip(
                resource_name,
                aws_access_key,
                aws_secret_key,
                aws_region
            )
        elif "missing tags" in issue.lower():
            result = remediate_ec2_tags(
                resource_name,
                aws_access_key,
                aws_secret_key,
                aws_region
            )
        else:
            result = {
                "success": False,
                "message": "Unknown EC2 issue type"
            }

        if result["success"]:
            update_status(resource_name)

        return result

    elif resource_type == "IAM User":
        result = remediate_iam_user(
            resource_name,
            issue,
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result["success"]:
            update_status(resource_name)

        return result

    elif resource_type == "CloudTrail":
        result = remediate_cloudtrail(
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result["success"]:
            update_status(resource_name)

        return result

    return {
        "success": False,
        "message": (
            f"Remediation not available for {resource_type}"
        )
    }


def auto_remediate_high_severity(
    aws_access_key=None,
    aws_secret_key=None,
    aws_region="us-east-1"
):
    """
    Automatically remediate HIGH severity findings.

    This function is kept for direct/background execution. The web scan
    normally uses process_remediation() from run_scan().
    """
    findings = load_findings()

    for finding in findings:
        # Never remediate something already marked resolved.
        if finding.get("status") in ["RESOLVED", "JUST RESOLVED"]:
            continue

        if finding.get("severity") != "HIGH":
            continue

        print(
            f"AUTO-REMEDIATING HIGH severity: "
            f"{finding.get('name')}"
        )

        result = process_remediation(
            finding.get("resource"),
            finding.get("name"),
            finding.get("issue"),
            aws_access_key,
            aws_secret_key,
            aws_region
        )

        if result.get("success"):
            print(
                f"✅ Fixed: {result.get('message')}"
            )
        else:
            print(
                f"❌ Failed: {result.get('message')}"
            )


if __name__ == "__main__":
    # Uses boto3's normal credential chain when no explicit credentials
    # are supplied. The web application should pass logged-in credentials.
    auto_remediate_high_severity()

    update_just_resolved_to_resolved(hours=1)