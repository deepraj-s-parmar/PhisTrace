# ThreatLens – Ubuntu Deployment Guide

## Overview
This guide covers deploying ThreatLens on an Ubuntu 20.04/22.04/24.04 server using:
- **Gunicorn** as the WSGI server
- **Nginx** as a reverse proxy
- **systemd** to keep the app running

---

## 1. System Requirements
- Ubuntu 20.04+ (VPS or dedicated)
- Python 3.9+
- 1 GB RAM minimum
- A domain name (optional but recommended)

---

## 2. Initial Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python, pip, nginx, git
sudo apt install -y python3 python3-pip python3-venv nginx git curl

# Create a dedicated user (optional but best practice)
sudo adduser --system --group threatlens
```

---

## 3. Upload / Clone the Project

```bash
# Option A: Git clone (if you have it in a repo)
cd /opt
sudo git clone https://your-repo-url/threat-analyzer.git threatlens
sudo chown -R threatlens:threatlens /opt/threatlens

# Option B: SCP from your local machine
scp -r ./threat-analyzer user@YOUR_SERVER_IP:/opt/threatlens
```

---

## 4. Python Virtual Environment & Dependencies

```bash
cd /opt/threatlens
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install gunicorn
```

---

## 5. Test the App

```bash
cd /opt/threatlens
source venv/bin/activate
python app.py
# Should print: Running on http://0.0.0.0:5000
# Press Ctrl+C to stop
```

---

## 6. Create a systemd Service

```bash
sudo nano /etc/systemd/system/threatlens.service
```

Paste this content:

```ini
[Unit]
Description=ThreatLens Security Analyzer
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/threatlens
Environment="PATH=/opt/threatlens/venv/bin"
Environment="DATABASE_PATH=/opt/threatlens/threats.db"
ExecStart=/opt/threatlens/venv/bin/gunicorn \
    --workers 4 \
    --bind 127.0.0.1:5000 \
    --timeout 120 \
    --access-logfile /var/log/threatlens/access.log \
    --error-logfile /var/log/threatlens/error.log \
    app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# Create log directory
sudo mkdir -p /var/log/threatlens
sudo chown www-data:www-data /var/log/threatlens

# Fix file permissions
sudo chown -R www-data:www-data /opt/threatlens

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable threatlens
sudo systemctl start threatlens

# Check it's running
sudo systemctl status threatlens
```

---

## 7. Configure Nginx

### Without SSL (HTTP only)

```bash
sudo nano /etc/nginx/sites-available/threatlens
```

```nginx
server {
    listen 80;
    server_name YOUR_DOMAIN_OR_IP;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";

    # Upload size limit (for future .eml uploads)
    client_max_body_size 10M;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120;
    }

    location /static/ {
        alias /opt/threatlens/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/threatlens /etc/nginx/sites-enabled/
sudo nginx -t           # Check config is valid
sudo systemctl reload nginx
```

### With SSL using Let's Encrypt (HTTPS – Recommended)

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get certificate (replace with your domain)
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Certbot auto-updates the Nginx config. Done!
# Test auto-renewal:
sudo certbot renew --dry-run
```

---

## 8. Open Firewall Ports

```bash
sudo ufw allow 'Nginx Full'   # ports 80 and 443
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status
```

---

## 9. Verify Everything Works

```bash
# App service is running
sudo systemctl status threatlens

# Nginx is running
sudo systemctl status nginx

# Test locally on the server
curl -s http://127.0.0.1:5000 | head -20

# Test API
curl -s -X POST http://127.0.0.1:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://paypal-security-verify.xyz/login"}' | python3 -m json.tool
```

Now visit `http://YOUR_IP` or `https://yourdomain.com` in your browser.

---

## 10. Useful Management Commands

```bash
# Restart the app (after code changes)
sudo systemctl restart threatlens

# View live app logs
sudo journalctl -u threatlens -f

# View Nginx access logs
sudo tail -f /var/log/nginx/access.log

# View app error logs
sudo tail -f /var/log/threatlens/error.log

# Update the code
cd /opt/threatlens
sudo git pull
sudo systemctl restart threatlens
```

---

## 11. Quick Troubleshooting

| Problem | Fix |
|---|---|
| 502 Bad Gateway | `sudo systemctl status threatlens` – app crashed? |
| Permission denied on DB | `sudo chown www-data:www-data /opt/threatlens/threats.db` |
| Port 5000 already in use | `sudo lsof -i :5000` then kill conflicting process |
| Module not found | Make sure venv is activated: `source venv/bin/activate` |
| Static files 404 | Check `alias /opt/threatlens/static/;` path in nginx config |

---

## 12. One-Command Quick Deploy Script

Save as `deploy.sh` in your project root and run `bash deploy.sh`:

```bash
#!/bin/bash
set -e
echo "=== ThreatLens Deploy ==="

apt update -q && apt install -y python3 python3-pip python3-venv nginx -q

mkdir -p /opt/threatlens
cp -r . /opt/threatlens/
cd /opt/threatlens

python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt gunicorn

mkdir -p /var/log/threatlens
chown www-data:www-data /var/log/threatlens /opt/threatlens

cat > /etc/systemd/system/threatlens.service << 'EOF'
[Unit]
Description=ThreatLens
After=network.target
[Service]
User=www-data
WorkingDirectory=/opt/threatlens
Environment="PATH=/opt/threatlens/venv/bin"
ExecStart=/opt/threatlens/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF

cat > /etc/nginx/sites-available/threatlens << 'EOF'
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    location /static/ { alias /opt/threatlens/static/; }
}
EOF

ln -sf /etc/nginx/sites-available/threatlens /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

systemctl daemon-reload
systemctl enable --now threatlens
systemctl reload nginx

echo "✅ Done! Visit http://$(hostname -I | awk '{print $1}')"
```

---

## Folder Structure

```
/opt/threatlens/
├── app.py            ← Flask application
├── analyzer.py       ← Threat analysis engine
├── requirements.txt
├── threats.db        ← SQLite database (auto-created)
├── venv/             ← Python virtual environment
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/app.js
```
