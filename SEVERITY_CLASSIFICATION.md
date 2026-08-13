# 🎯 Configuards Severity Classification Guide

## Complete List of Detections by Severity

---

## 🚨 HIGH Severity (Auto-Fix Immediately)

### Definition
Immediate security risk. Anyone on the internet could access or misuse the resource.

### Detections

#### S3 Buckets
- ✅ **S3 bucket publicly accessible**
  - Detection: `get_bucket_policy_status()` returns IsPublic=True
  - Remediation: Block all public access
  - API: `put_public_access_block()`

#### Security Groups
- ✅ **Security group open to 0.0.0.0/0 on sensitive ports**
  - Ports: 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 1433 (SQL Server), 27017 (MongoDB)
  - Detection: IpPermissions with CidrIp=0.0.0.0/0 on sensitive ports
  - Remediation: Revoke ingress rules
  - API: `revoke_security_group_ingress()`

#### IAM
- ✅ **IAM user with AdministratorAccess**
  - Detection: User has AdministratorAccess policy attached
  - Remediation: Detach policy (manual review recommended)
  - API: `detach_user_policy()`

- ✅ **IAM access keys exposed or very old (>180 days)**
  - Detection: Access key age > 180 days
  - Remediation: Deactivate old keys
  - API: `update_access_key(Status='Inactive')`

### Remediation Rule
⚡ **AUTO FIX IMMEDIATELY** - No user interaction, fixes during scan

---

## ⚠️ MEDIUM Severity (Timer-Based Fix)

### Definition
Security weakness that could become dangerous but is not immediately exploitable.

### Detections

#### Security Groups
- ✅ **Security group open to internet on non-critical ports**
  - Ports: Any port except sensitive ones
  - Detection: IpPermissions with CidrIp=0.0.0.0/0 on non-sensitive ports
  - Remediation: Revoke ingress rules after approval

#### EC2
- ✅ **EC2 instance has public IP**
  - Detection: Instance has PublicIpAddress and is running
  - Remediation: Review and potentially move to private subnet

#### IAM
- ✅ **Unused IAM users (inactive >90 days)**
  - Detection: PasswordLastUsed > 90 days ago
  - Remediation: Disable or delete user

- ✅ **IAM policies with excessive permissions**
  - Detection: User has >5 inline policies
  - Remediation: Consolidate policies

- ✅ **Old access keys (>90 days but <180 days)**
  - Detection: Access key age between 90-180 days
  - Remediation: Rotate keys

### Remediation Rule
⏱️ **WARN USER → WAIT 30s → THEN AUTO FIX**
- Shows timer modal
- User can approve, deny, or wait
- Auto-executes after 30 seconds

---

## 📋 LOW Severity (Log Only)

### Definition
Best-practice violations. No immediate danger.

### Detections

#### S3
- ✅ **S3 bucket missing tags**
  - Detection: No tags configured on bucket
  - Remediation: None (manual tagging recommended)

#### EC2
- ✅ **EC2 instance missing tags**
  - Detection: No tags on instance
  - Remediation: None (manual tagging recommended)

- ✅ **Unused EC2 instances (stopped >30 days)**
  - Detection: Instance in 'stopped' state for >30 days
  - Remediation: None (manual review/termination)

#### CloudTrail
- ✅ **CloudTrail logging disabled**
  - Detection: No trails configured or IsLogging=False
  - Remediation: None (manual enablement recommended)

#### IAM
- ✅ **Weak password policy**
  - Detection: MinimumPasswordLength < 14
  - Remediation: None (manual policy update)

- ✅ **No password policy configured**
  - Detection: get_account_password_policy() fails
  - Remediation: None (manual policy creation)

### Remediation Rule
📝 **LOG ONLY (NO AUTO FIX)**
- Display on dashboard
- No automatic remediation
- Manual review required

---

## 📊 Detection Summary

### Total Checks: 17

| Severity | Count | Auto-Fix |
|----------|-------|----------|
| HIGH     | 4     | ✅ Yes (Immediate) |
| MEDIUM   | 6     | ⏱️ Yes (Timer) |
| LOW      | 7     | ❌ No (Manual) |

---

## 🔧 Technical Implementation

### Detector Files Updated

1. **s3_detector.py**
   - HIGH: Public buckets
   - LOW: Missing tags

2. **sg_detector.py**
   - HIGH: Sensitive ports open (22, 3389, 3306, 5432, 1433, 27017)
   - MEDIUM: Non-critical ports open

3. **iam_detector.py**
   - HIGH: AdministratorAccess, Very old keys (>180 days)
   - MEDIUM: Unused users, Excessive permissions, Old keys (>90 days)
   - LOW: Weak password policy

4. **ec2_detector.py**
   - MEDIUM: Public IP instances
   - LOW: Missing tags, Unused instances, CloudTrail disabled

---

## 🚀 Scan Flow

```
Run Scan
    ↓
Detect all issues
    ↓
Classify by severity
    ↓
HIGH → Auto-fix immediately
    ↓
MEDIUM → Show on UI with timer button
    ↓
LOW → Show on UI (info only)
    ↓
Update security_findings.json
    ↓
Display on dashboard
```

---

## 📈 Expected Results

After running a scan on a typical AWS account:

**HIGH Severity:**
- 0-5 findings (should be rare)
- Auto-fixed during scan
- Status: RESOLVED

**MEDIUM Severity:**
- 5-20 findings (common)
- Requires user approval
- Status: OPEN (until fixed)

**LOW Severity:**
- 10-50 findings (very common)
- Informational only
- Status: OPEN (manual review)

---

## 🎯 Best Practices

1. **Run scans regularly** (daily recommended)
2. **Review MEDIUM findings** within 24 hours
3. **Address LOW findings** during maintenance windows
4. **Monitor compliance score** (should be >90%)
5. **Keep audit trail** of all remediations

---

**Last Updated**: 2024
**Version**: 2.0
**System**: Configuards CSPM
