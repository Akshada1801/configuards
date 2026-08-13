# Configuards - AWS Security Scanner & Auto-Remediation System

A comprehensive cloud security monitoring and auto-remediation platform for AWS infrastructure.

## 🚀 Features

- **Real-time AWS Security Scanning**: S3, EC2, IAM, Security Groups
- **Three-Tier Auto-Remediation System**:
  - 🤖 **HIGH**: Auto-fix immediately during scan
  - ⏱️ **MEDIUM**: Manual remediation with button
  - 🔧 **LOW**: Manual review and fix
- **17 Security Checks** across AWS services
- **Smart Status Tracking**: OPEN → JUST RESOLVED → RESOLVED
- **Modern Dashboard** with real-time statistics
- **Duplicate Prevention**: Resolved issues stay resolved

## 📋 Security Checks

### HIGH Severity (Auto-Remediated)
- S3 buckets with public access
- Security groups with SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432) open to 0.0.0.0/0
- IAM users with AdministratorAccess policy
- IAM access keys older than 180 days

### MEDIUM Severity (Manual Remediation)
- Security groups with non-critical ports open to internet
- IAM users inactive for 90+ days
- IAM users with excessive permissions
- IAM access keys 90-180 days old
- EC2 instances with public IP addresses

### LOW Severity (Manual Review)
- S3 buckets missing tags
- EC2 instances missing tags
- EC2 instances stopped for 30+ days
- CloudTrail disabled
- Weak IAM password policy

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- AWS CLI configured with credentials
- AWS account with appropriate permissions

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/configuards.git
cd configuards
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure AWS credentials**
```bash
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Enter default region (e.g., us-east-1)
```

4. **Create required files**
```bash
# Copy example files
cp users.json.example users.json
cp security_findings.json.example security_findings.json
```

5. **Run the application**
```bash
python app.py
```

6. **Access the dashboard**
```
http://localhost:5000
```

## 📖 Usage

### First Time Setup
1. Navigate to `http://localhost:5000`
2. Click **Sign Up** and create an account
3. Login with your credentials

### Running Security Scans
1. Go to **Dashboard**
2. Click **Scan Resources** button
3. Wait for scan to complete
4. HIGH severity issues are auto-remediated
5. View findings in **Findings** page

### Remediating Issues
- **HIGH**: Already fixed during scan
- **MEDIUM**: Click "🔧 Remediate" button
- **LOW**: Click "🔧 Manual Fix" button

### Clearing Resolved Issues
1. Go to **Dashboard**
2. Click **Clear Resolved** button
3. Confirms removal of all resolved findings

## 🏗️ Project Structure

```
configuards/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── users.json                  # User accounts (gitignored)
├── security_findings.json      # Scan results (gitignored)
├── detection/
│   ├── detector_engine.py      # Main scan orchestrator
│   ├── s3_detector.py          # S3 security checks
│   ├── ec2_detector.py         # EC2 security checks
│   ├── iam_detector.py         # IAM security checks
│   └── sg_detector.py          # Security Group checks
├── remediation/
│   └── remediation_engine.py   # Auto-remediation logic
├── templates/
│   ├── dashboard.html          # Main dashboard
│   ├── findings.html           # Findings page
│   ├── reports.html            # Reports page
│   ├── profile.html            # User profile
│   ├── login.html              # Login page
│   └── signup.html             # Signup page
└── static/
    └── css/
        └── style.css           # Application styles
```

## 🧪 Testing (Free Tier)

See test cases that won't cost you anything:

```bash
# Test 1: Public S3 Bucket (HIGH)
aws s3 mb s3://test-bucket-$(date +%s)
aws s3api put-bucket-acl --bucket test-bucket-XXXXX --acl public-read

# Test 2: SSH Port Open (HIGH)
aws ec2 create-security-group --group-name test-sg --description "Test"
aws ec2 authorize-security-group-ingress --group-name test-sg --protocol tcp --port 22 --cidr 0.0.0.0/0

# Test 3: IAM Admin User (HIGH)
aws iam create-user --user-name test-user
aws iam attach-user-policy --user-name test-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Run scan in Configuards dashboard

# Cleanup
aws s3 rb s3://test-bucket-XXXXX --force
aws ec2 delete-security-group --group-name test-sg
aws iam detach-user-policy --user-name test-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name test-user
```

## 🔒 Security Notes

- Never commit `users.json` or `security_findings.json`
- Never commit AWS credentials
- Use AWS IAM roles with least privilege
- Keep dependencies updated
- Use HTTPS in production

## 📊 Dashboard Features

- **Real-time Statistics**: Low, High, Medium, Resolved counts
- **Compliance Score**: Calculated based on open issues
- **Recent Activity**: Track scan history
- **Quick Actions**: Scan and clear resolved findings
- **Status Transitions**: Visual tracking of issue lifecycle

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

## 👤 Author

Your Name - [GitHub Profile](https://github.com/YOUR_USERNAME)

## 🙏 Acknowledgments

- AWS SDK for Python (Boto3)
- Flask Web Framework
- Bootstrap CSS Framework
