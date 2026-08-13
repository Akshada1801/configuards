from log_system.logger import log_finding
import boto3


def scan_security_groups(aws_access_key=None, aws_secret_key=None, aws_region='us-east-1'):
    """Scan security groups for open ports"""
    findings = []
    ec2 = boto3.client('ec2',
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
        groups = ec2.describe_security_groups()
    except Exception as e:
        print(f"Error scanning security groups: {e}")
        return findings
    
    # Sensitive ports for HIGH severity
    sensitive_ports = [22, 3389, 3306, 5432, 1433, 27017]
    
    for group in groups['SecurityGroups']:
        group_id = group['GroupId']
        group_name = group.get('GroupName', group_id)
        
        # Skip if already resolved
        if group_id in resolved_resources:
            continue
        
        for rule in group['IpPermissions']:
            if 'IpRanges' in rule:
                for ip in rule['IpRanges']:
                    if ip['CidrIp'] == "0.0.0.0/0":
                        
                        # Get port range
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 65535)
                        
                        # HIGH: Sensitive ports open to internet
                        if any(port in range(from_port, to_port + 1) for port in sensitive_ports):
                            severity = "HIGH"
                            issue = f"Sensitive port {from_port} open to internet (0.0.0.0/0)"
                            log_finding("Security Group", group_id, issue, "HIGH")
                        else:
                            # MEDIUM: Non-critical ports open to internet
                            severity = "MEDIUM"
                            issue = f"Port {from_port} open to internet (0.0.0.0/0)"
                        
                        findings.append({
                            "resource": "Security Group",
                            "name": group_id,
                            "issue": issue,
                            "severity": severity,
                            "status": "OPEN"
                        })
    
    return findings