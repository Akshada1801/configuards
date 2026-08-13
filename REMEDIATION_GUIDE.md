# 🛡️ Configuards Remediation System Guide

## Overview
Configuards implements a **three-tier remediation system** based on severity levels, following industry best practices for Cloud Security Posture Management (CSPM).

---

## 🚨 Severity Levels & Remediation Rules

### 1️⃣ HIGH Severity
**Definition:** Immediate security risk. Anyone on the internet could access or misuse the resource.

**Examples:**
- S3 bucket publicly accessible
- Security group open to 0.0.0.0/0 on sensitive ports (22, 3389)
- IAM user with AdministratorAccess
- IAM access keys exposed or very old

**Remediation Rule:** ⚡ **AUTO FIX IMMEDIATELY**

**Actions:**
- Block S3 public access
- Remove open security group rules
- Disable risky IAM permissions

**UI Behavior:**
- Red "Auto Fix Now" button
- Single confirmation dialog
- Executes immediately upon approval
- No waiting period

---

### 2️⃣ MEDIUM Severity
**Definition:** Security weakness that could become dangerous but is not immediately exploitable.

**Examples:**
- Security group open to internet on non-critical ports
- Unused IAM users
- IAM policies with excessive permissions
- Old access keys (>90 days)

**Remediation Rule:** ⏱️ **WARN USER → WAIT → THEN AUTO FIX**

**Actions:**
- Notify user with modal dialog
- Start 30-second countdown timer
- User can approve or deny
- If no action taken, auto-fix proceeds

**UI Behavior:**
- Yellow "Fix with Timer" button
- Opens modal with countdown
- Shows resource details
- Two options: Approve or Deny
- Auto-executes after 30 seconds

---

### 3️⃣ LOW Severity
**Definition:** Best-practice violations. No immediate danger.

**Examples:**
- Resources missing tags
- CloudTrail logging disabled
- Weak password policy
- Unused EC2 instances

**Remediation Rule:** 📋 **LOG ONLY (NO AUTO FIX)**

**Actions:**
- Display on dashboard
- No automatic remediation
- Manual review required

**UI Behavior:**
- Gray "Manual Review" text
- No action button
- Informational only

---

## 🎯 How to Use the Remediation System

### Step 1: Navigate to Findings Page
```
Dashboard → Findings
```

### Step 2: Identify Issues by Severity
- **RED badge** = HIGH severity
- **YELLOW badge** = MEDIUM severity
- **BLUE badge** = LOW severity

### Step 3: Remediate Based on Severity

#### For HIGH Severity:
1. Click "Auto Fix Now" button
2. Confirm in dialog
3. System fixes immediately
4. Status updates to "RESOLVED"

#### For MEDIUM Severity:
1. Click "Fix with Timer" button
2. Modal opens with 30-second countdown
3. Options:
   - **Approve Now**: Fix immediately
   - **Deny**: Cancel remediation
   - **Wait**: Auto-fix after timer expires
4. Status updates to "RESOLVED" after fix

#### For LOW Severity:
1. Review the issue
2. Take manual action if needed
3. No automated fix available

---

## 🔧 Technical Implementation

### Remediation Flow
```
User clicks button
    ↓
JavaScript validates
    ↓
POST /remediate
    ↓
process_remediation()
    ↓
AWS API calls (boto3)
    ↓
Update security_findings.json
    ↓
Return success/failure
    ↓
Update UI
```

### Supported Remediations

#### S3 Buckets
- **Issue**: Public access enabled
- **Fix**: Apply public access block
- **API**: `put_public_access_block()`

#### Security Groups
- **Issue**: Open to 0.0.0.0/0
- **Fix**: Revoke ingress rules
- **API**: `revoke_security_group_ingress()`

---

## 📊 Remediation Statistics

After remediation:
- Dashboard stats update automatically
- Compliance score increases
- Resolved count increments
- Open issues decrease

---

## 🔐 Security Considerations

1. **AWS Credentials**: Uses AWS CLI credentials (boto3 default)
2. **Permissions Required**:
   - `s3:PutPublicAccessBlock`
   - `ec2:RevokeSecurityGroupIngress`
   - `ec2:DescribeSecurityGroups`
3. **Audit Trail**: All actions logged with timestamps
4. **Rollback**: Manual rollback required if needed

---

## 🎨 UI Components

### Buttons
- **Auto Fix Now** (Red): HIGH severity
- **Fix with Timer** (Yellow): MEDIUM severity
- **Manual Review** (Gray): LOW severity
- **✓ Resolved** (Green): Already fixed

### Timer Modal
- Countdown display (30 seconds)
- Approve button (Green)
- Deny button (Red)
- Auto-close on completion

---

## 🚀 Best Practices

1. **Review before fixing**: Always check resource details
2. **Test in dev first**: Try on non-production resources
3. **Monitor after fix**: Verify applications still work
4. **Keep backups**: Have rollback plan ready
5. **Document changes**: Note what was fixed and when

---

## 📝 Example Workflow

### Scenario: Public S3 Bucket Detected

1. **Detection**: Scan finds public S3 bucket
2. **Classification**: Marked as HIGH severity
3. **Alert**: Shows on dashboard with red badge
4. **Remediation**:
   - User clicks "Auto Fix Now"
   - Confirms action
   - System blocks public access
   - Status → RESOLVED
5. **Verification**: Bucket no longer public
6. **Reporting**: Compliance score increases

---

## 🛠️ Troubleshooting

### Issue: Remediation fails
**Solution**: Check AWS credentials and permissions

### Issue: Timer doesn't start
**Solution**: Refresh page and try again

### Issue: Status not updating
**Solution**: Click "Clear Resolved" to refresh data

---

## 📞 Support

For issues or questions:
1. Check AWS CloudTrail logs
2. Review browser console for errors
3. Verify boto3 credentials
4. Check security_findings.json format

---

**Last Updated**: 2024
**Version**: 1.0
**System**: Configuards CSPM
