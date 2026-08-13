import boto3
from datetime import datetime, timedelta

def scan_iam(aws_access_key=None, aws_secret_key=None, aws_region='us-east-1'):
    """Scan IAM for security issues"""
    findings = []
    iam = boto3.client('iam',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
    
    try:
        users = iam.list_users()
    except Exception as e:
        print(f"Error scanning IAM: {e}")
        return findings
    
    for user in users['Users']:
        user_name = user['UserName']
        
        # HIGH: IAM user with AdministratorAccess
        try:
            policies = iam.list_attached_user_policies(UserName=user_name)
            for policy in policies['AttachedPolicies']:
                if policy['PolicyName'] == "AdministratorAccess":
                    findings.append({
                        "resource": "IAM User",
                        "name": user_name,
                        "issue": "User has AdministratorAccess policy",
                        "severity": "HIGH",
                        "status": "OPEN"
                    })
        except:
            pass
        
        # Check access keys
        try:
            keys = iam.list_access_keys(UserName=user_name)
            for key in keys['AccessKeyMetadata']:
                key_id = key['AccessKeyId']
                create_date = key['CreateDate'].replace(tzinfo=None)
                age_days = (datetime.now() - create_date).days
                
                # HIGH: Very old access keys (>180 days)
                if age_days > 180:
                    findings.append({
                        "resource": "IAM Access Key",
                        "name": key_id,
                        "issue": f"Access key is {age_days} days old (exposed/very old)",
                        "severity": "HIGH",
                        "status": "OPEN"
                    })
                # MEDIUM: Old access keys (>90 days)
                elif age_days > 90:
                    findings.append({
                        "resource": "IAM Access Key",
                        "name": key_id,
                        "issue": f"Access key is {age_days} days old",
                        "severity": "MEDIUM",
                        "status": "OPEN"
                    })
        except:
            pass
        
        # MEDIUM: Unused IAM users (no activity in 90 days)
        try:
            last_used = iam.get_user(UserName=user_name)['User'].get('PasswordLastUsed')
            if last_used:
                last_used = last_used.replace(tzinfo=None)
                inactive_days = (datetime.now() - last_used).days
                if inactive_days > 90:
                    findings.append({
                        "resource": "IAM User",
                        "name": user_name,
                        "issue": f"User inactive for {inactive_days} days",
                        "severity": "MEDIUM",
                        "status": "OPEN"
                    })
        except:
            pass
        
        # MEDIUM: IAM policies with excessive permissions
        try:
            inline_policies = iam.list_user_policies(UserName=user_name)
            if len(inline_policies['PolicyNames']) > 5:
                findings.append({
                    "resource": "IAM User",
                    "name": user_name,
                    "issue": f"User has {len(inline_policies['PolicyNames'])} inline policies (excessive permissions)",
                    "severity": "MEDIUM",
                    "status": "OPEN"
                })
        except:
            pass
    
    return findings