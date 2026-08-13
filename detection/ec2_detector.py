import boto3
from datetime import datetime, timedelta

def scan_ec2(aws_access_key=None, aws_secret_key=None, aws_region='us-east-1'):
    """Scan EC2 instances for security issues"""
    findings = []
    ec2 = boto3.client('ec2',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
    cloudtrail = boto3.client('cloudtrail',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
    
    try:
        instances = ec2.describe_instances()
    except Exception as e:
        print(f"Error scanning EC2: {e}")
        return findings
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            state = instance['State']['Name']
            
            # MEDIUM: Instance has public IP
            if 'PublicIpAddress' in instance and state == 'running':
                findings.append({
                    "resource": "EC2 Instance",
                    "name": instance_id,
                    "issue": "Instance has public IP address",
                    "severity": "MEDIUM",
                    "status": "OPEN"
                })
            
            # LOW: Resources missing tags
            tags = instance.get('Tags', [])
            if not tags or len(tags) == 0:
                findings.append({
                    "resource": "EC2 Instance",
                    "name": instance_id,
                    "issue": "Instance missing tags",
                    "severity": "LOW",
                    "status": "OPEN"
                })
            
            # LOW: Unused EC2 instances (stopped for long time)
            if state == 'stopped':
                launch_time = instance.get('LaunchTime')
                if launch_time:
                    launch_time = launch_time.replace(tzinfo=None)
                    stopped_days = (datetime.now() - launch_time).days
                    if stopped_days > 30:
                        findings.append({
                            "resource": "EC2 Instance",
                            "name": instance_id,
                            "issue": f"Instance stopped for {stopped_days} days (unused)",
                            "severity": "LOW",
                            "status": "OPEN"
                        })
    
    # LOW: CloudTrail logging disabled
    try:
        trails = cloudtrail.describe_trails()
        if not trails['trailList']:
            findings.append({
                "resource": "CloudTrail",
                "name": "Account CloudTrail",
                "issue": "CloudTrail logging disabled",
                "severity": "LOW",
                "status": "OPEN"
            })
        else:
            # Check if trails are actually logging
            for trail in trails['trailList']:
                trail_name = trail['Name']
                status = cloudtrail.get_trail_status(Name=trail_name)
                if not status.get('IsLogging', False):
                    findings.append({
                        "resource": "CloudTrail",
                        "name": trail_name,
                        "issue": "CloudTrail logging disabled",
                        "severity": "LOW",
                        "status": "OPEN"
                    })
    except:
        pass
    
    return findings