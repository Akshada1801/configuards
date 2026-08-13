# Production Deployment Guide

## Prerequisites

- Python 3.8+
- AWS Account with IAM credentials
- Domain name (optional)
- SSL certificate (recommended)

## Step 1: Server Setup

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx
```

### CentOS/RHEL
```bash
sudo yum install python3-pip nginx
```

## Step 2: Application Setup

```bash
# Create application directory
sudo mkdir -p /var/www/configuards
cd /var/www/configuards

# Clone or copy application files
# Upload your configuards folder here

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install gunicorn
```

## Step 3: Configure Gunicorn

Create `/etc/systemd/system/configuards.service`:

```ini
[Unit]
Description=Configuards Cloud Security Platform
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/configuards
Environment="PATH=/var/www/configuards/venv/bin"
ExecStart=/var/www/configuards/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:8000 app:app

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable configuards
sudo systemctl start configuards
sudo systemctl status configuards
```

## Step 4: Configure Nginx

Create `/etc/nginx/sites-available/configuards`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static {
        alias /var/www/configuards/static;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/configuards /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Step 5: SSL Setup (Let's Encrypt)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Step 6: Security Hardening

```bash
# Set proper permissions
sudo chown -R www-data:www-data /var/www/configuards
sudo chmod -R 755 /var/www/configuards

# Secure sensitive files
sudo chmod 600 /var/www/configuards/users.json
sudo chmod 600 /var/www/configuards/feedback.json
```

## Step 7: Monitoring

```bash
# View logs
sudo journalctl -u configuards -f

# Check status
sudo systemctl status configuards
```

## Environment Variables

Create `.env` file:
```bash
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:pass@localhost/configuards
```

## Backup Strategy

```bash
# Daily backup script
#!/bin/bash
DATE=$(date +%Y%m%d)
tar -czf /backups/configuards-$DATE.tar.gz /var/www/configuards/users.json /var/www/configuards/feedback.json
```

## Maintenance

```bash
# Update application
cd /var/www/configuards
git pull
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart configuards
```

## Troubleshooting

### Application won't start
```bash
sudo journalctl -u configuards -n 50
```

### Permission errors
```bash
sudo chown -R www-data:www-data /var/www/configuards
```

### Port already in use
```bash
sudo lsof -i :8000
sudo kill -9 <PID>
```

## Performance Tuning

### Gunicorn workers
```bash
# Formula: (2 x CPU cores) + 1
gunicorn --workers 9 --bind 127.0.0.1:8000 app:app
```

### Nginx caching
Add to nginx config:
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m;
proxy_cache my_cache;
```

## Success!

Your Configuards platform is now running in production at https://your-domain.com
