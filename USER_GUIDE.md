# Configuards User Guide

## Table of Contents
1. Getting Started
2. Dashboard Overview
3. AWS Configuration
4. Security Scanning
5. Findings Management
6. Auto-Remediation
7. Reports & Compliance
8. Settings & Preferences
9. Troubleshooting

---

## 1. Getting Started

### Creating Your Account
1. Navigate to the Configuards login page
2. Click "Sign up here"
3. Fill in your details:
   - Full Name
   - Mobile Number
   - Email Address
   - AWS Builder ID
   - Password (minimum 8 characters recommended)
4. Click "Sign Up"
5. You'll be redirected to the login page

### First Login
1. Enter your email and password
2. Click "Login"
3. You'll see the dashboard with setup instructions

---

## 2. Dashboard Overview

The dashboard provides a real-time view of your cloud security posture:

### Statistics Cards
- **Critical Issues**: Immediate attention required
- **High Severity**: Important security concerns
- **Medium Severity**: Moderate risk items
- **Resolved**: Successfully fixed issues

### Compliance Score
- Displayed as a percentage (0-100%)
- Calculated based on total findings
- Higher score = better security posture

### Quick Actions
- **View All Findings**: See detailed security issues
- **Generate Report**: Create downloadable reports
- **Scan Resources**: Trigger new AWS scan

### Recent Activity
- Real-time feed of security events
- Scan completion notifications
- Finding detection alerts

---

## 3. AWS Configuration

### Setting Up AWS Credentials

1. **Go to Profile**
   - Click your profile icon → Profile

2. **Click "Edit Profile"**

3. **Add AWS Credentials**
   - AWS Access Key: Your IAM access key
   - AWS Secret Key: Your IAM secret key
   - AWS Region: Select your primary region

4. **Save Changes**

### Creating AWS IAM User

1. Log into AWS Console
2. Go to IAM → Users → Add User
3. Enable "Programmatic access"
4. Attach policies:
   - AmazonS3ReadOnlyAccess
   - AmazonEC2ReadOnlyAccess
   - For remediation: S3FullAccess, EC2FullAccess
5. Save Access Key and Secret Key
6. Add them to Configuards Profile

---

## 4. Security Scanning

### Manual Scan
1. Go to Dashboard
2. Click "Scan Resources" button
3. Wait for scan to complete (5-10 seconds)
4. View results on dashboard

### What Gets Scanned

**S3 Buckets**
- Public access configuration
- ACL permissions
- Bucket policies

**Security Groups**
- Ingress rules
- Open ports (0.0.0.0/0)
- Critical port exposure (22, 3389, 3306, 5432)

**EC2 Instances**
- EBS volume encryption
- Running instance status
- Security group associations

---

## 5. Findings Management

### Viewing Findings
1. Click "Findings" in navigation
2. See table with all detected issues

### Finding Details
Each finding shows:
- **Resource Type**: S3, EC2, Security Group, etc.
- **Resource Name**: Specific resource identifier
- **Issue**: Description of the problem
- **Severity**: High, Medium, Low
- **Status**: Open or Resolved
- **Action**: Fix button (if available)

### Severity Levels

**High (Red)**
- Public S3 buckets
- Critical ports open to internet
- Immediate security risks

**Medium (Yellow)**
- Non-critical open ports
- Unencrypted volumes
- Moderate security concerns

---

## 6. Auto-Remediation

### Fixing Issues

1. **Navigate to Findings**
2. **Locate the issue** you want to fix
3. **Click "Fix Issue"** button
4. **Confirm the action** in the popup
5. **Wait for completion** (1-2 seconds)
6. **Verify success** message

### What Can Be Fixed

**S3 Buckets**
- ✅ Automatically blocks public access
- ✅ Applies public access block configuration
- ✅ Secures bucket ACLs

**Security Groups**
- ✅ Removes 0.0.0.0/0 ingress rules
- ✅ Closes dangerous open ports
- ✅ Maintains other necessary rules

**EC2 Instances**
- ❌ Manual fix required (encryption can't be added to existing volumes)

### Safety Features
- **Permission Required**: You must approve each fix
- **Confirmation Dialog**: Double-check before applying
- **Audit Trail**: All actions are logged
- **Rollback Info**: Details provided for manual rollback if needed

---

## 7. Reports & Compliance

### Generating Reports

1. **Go to Reports** page
2. **Choose report type**:
   - Weekly Security Summary
   - Compliance Report
   - Resource Inventory
3. **Click "Download Report"**
4. **Save the .txt file**

### Report Contents
- Report metadata (date, user, region)
- Summary statistics
- Detailed findings list
- Severity breakdown
- Compliance score
- Recommendations

### Using Reports
- Share with security team
- Track progress over time
- Compliance documentation
- Audit evidence

---

## 8. Settings & Preferences

### Notification Settings
- **Email Alerts**: Critical finding notifications
- **Weekly Reports**: Automated summary emails
- **SMS Alerts**: High severity notifications
- **Push Notifications**: Browser alerts

### Scan Settings
- **Automatic Scans**: Daily scheduled scans
- **Real-time Monitoring**: Continuous checking
- **Include Archived**: Scan stopped resources
- **Deep Scan**: Comprehensive analysis

### Security Settings
- **Change Password**: Update your password
- **Two-Factor Authentication**: Enable/disable 2FA
- **AWS Credentials**: Update access keys
- **Session Management**: Active session control

### Privacy Settings
- **Data Collection**: Usage analytics
- **Activity Logging**: Action history
- **Report Sharing**: Team collaboration

---

## 9. Troubleshooting

### Common Issues

**"AWS credentials not configured"**
- Solution: Add AWS keys in Profile page

**"Scan failed"**
- Check AWS credentials are valid
- Verify IAM permissions
- Ensure network connectivity

**"Fix failed"**
- Verify IAM user has write permissions
- Check resource still exists
- Review AWS service limits

**"No findings detected"**
- This is good! Your AWS account is secure
- Try scanning different regions
- Verify AWS credentials are correct

### Getting Help

**In-App Support**
- Go to Feedback page
- Describe your issue
- Rate your experience
- Submit feedback

**Best Practices**
- Keep AWS credentials up to date
- Run scans regularly (daily recommended)
- Fix high severity issues immediately
- Review reports weekly
- Update settings as needed

---

## Quick Reference

### Keyboard Shortcuts
- None currently (feature coming soon)

### Important Links
- Dashboard: Main security overview
- Findings: Detailed issue list
- Reports: Download security reports
- Profile: AWS credentials setup
- Settings: Preferences and configuration

### Security Tips
1. Use strong passwords
2. Enable two-factor authentication
3. Limit AWS IAM permissions to minimum required
4. Review findings daily
5. Fix high severity issues immediately
6. Generate weekly reports
7. Keep AWS credentials secure
8. Log out when finished

---

**Need More Help?**
Contact support through the Feedback page or refer to the technical documentation.

**Configuards - Your Cloud Security Partner** 🔒
