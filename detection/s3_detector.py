import boto3
from log_system.logger import log_finding

def scan_s3(aws_access_key=None, aws_secret_key=None, aws_region='us-east-1'):
    """Scan S3 buckets for security issues"""
    findings = []
    s3 = boto3.client('s3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )
    
    # Load existing findings to avoid duplicates
    try:
        import json
        with open('security_findings.json', 'r') as f:
            existing = json.load(f)
        resolved_resources = {f['name'] for f in existing if f.get('status') in ['RESOLVED', 'JUST RESOLVED']}
    except:
        resolved_resources = set()
    
    try:
        buckets = s3.list_buckets()
    except Exception as e:
        print(f"Error listing S3 buckets: {e}")
        return findings
    
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        
        # Skip if already resolved
        if bucket_name in resolved_resources:
            continue
        
        # HIGH: Public bucket accessible
        try:
            status = s3.get_bucket_policy_status(Bucket=bucket_name)
            if status['PolicyStatus']['IsPublic']:
                log_finding("S3", bucket_name, "Public bucket", "HIGH")
                findings.append({
                    "resource": "S3",
                    "name": bucket_name,
                    "issue": "Publicly accessible bucket",
                    "severity": "HIGH",
                    "status": "OPEN"
                })
        except:
            pass
        
        # LOW: Missing tags
        try:
            tags = s3.get_bucket_tagging(Bucket=bucket_name)
        except:
            findings.append({
                "resource": "S3",
                "name": bucket_name,
                "issue": "Bucket missing tags",
                "severity": "LOW",
                "status": "OPEN"
            })
    
    return findings