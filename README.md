<div align="center">

<br/>

```
         ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗██╗     ███████╗███╗   ██╗███████╗
         ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║     ██╔════╝████╗  ██║██╔════╝
            ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     █████╗  ██╔██╗ ██║███████╗
            ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══╝  ██║╚██╗██║╚════██║
            ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████╗███████╗██║ ╚████║███████║
            ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
```

**Enterprise URL & Email Intelligence Platform**
https://phishtrace.parrysecurity.online/

*73+ security engines · Phishing detection · Email forensics · Live threat intelligence*

<br/>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Active-10b981?style=for-the-badge)]()

<br/>

> A **professional-grade cybersecurity intelligence platform** — analyze URLs and emails for phishing, malware, and social engineering threats using 73+ security engines, 500+ detection signatures, and real-time IOC feeds, with a live dashboard, batch scanning, and geographic threat attribution.

<br/>

---

</div>

<br/>

## ◈ Table of Contents

- [Overview](#-overview)
- [Detection Capabilities](#-detection-capabilities)
- [Risk Scoring](#-risk-scoring)
- [Architecture](#-architecture)
- [Dashboard Modules](#-dashboard-modules)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Performance](#-performance)
- [Security Model](#-security-model)
- [Docker Deployment](#-docker-deployment)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

<br/>

---

## ◈ Overview

ThreatLens is a **self-hosted URL and email threat intelligence platform** that consolidates multi-engine scanning, header forensics, pattern recognition, and live IOC feeds into a single analyst interface. It is designed for security teams that need fast, actionable verdicts on suspicious links and email content without sending data to external SaaS platforms.

```
                    Suspicious URL or Email Content
                                   │
                                   ▼
        ┌───────────────────────────────────────────────────────┐
        │             THREATLENS DETECTION ENGINE               │
        │                                                       │
        │  ┌─────────────────┐      ┌─────────────────────────┐ │
        │  │   URL Analyzer  │      │    Email Forensics      │ │
        │  │                 │      │                         │ │
        │  │ 73+ engines     │      │ Header validation       │ │
        │  │ Domain WHOIS    │      │ SPF/DKIM/DMARC          │ │
        │  │ SSL validation  │      │ Phishing language       │ │
        │  │ Typosquatting   │      │ Social engineering      │ │
        │  │ Redirect chains │      │ Embedded URL scan       │ │
        │  └────────┬────────┘      └───────────┬─────────────┘ │
        │           └──────────┬────────────────┘               │
        │                      ▼                                │
        │         ┌────────────────────────┐                    │
        │         │   Pattern Recognition  │                    │
        │         │   500+ signatures      │                    │
        │         └────────────┬───────────┘                    │
        │                      ▼                                │
        │         ┌────────────────────────┐                    │
        │         │   Risk Scoring Engine  │                    │
        │         │   0 – 100              │                    │
        │         └────────────┬───────────┘                    │
        └──────────────────────┼────────────────────────────────┘
                               │
                  ┌────────────┴────────────┐
                  ▼                         ▼
           Verdict + Report           SQLite Storage
           (dashboard / API)          (history / intel)
```

<br/>

---

## ◈ Detection Capabilities

### URL Analysis — 30+ Methods

| # | Method | What It Catches |
|---|--------|-----------------|
| 1 | **73+ Security Engines** | Multi-engine malware and phishing consensus |
| 2 | **Domain Age Analysis** | Domains < 30 days flagged as suspicious |
| 3 | **Suspicious TLD Detection** | `.tk .xyz .top .ml .ga` and 20+ high-abuse TLDs |
| 4 | **Typosquatting Detection** | Levenshtein distance against known brand domains |
| 5 | **Homoglyph Attack Detection** | Unicode character substitution (e.g., `pаypal.com`) |
| 6 | **SSL Certificate Validation** | Expired, self-signed, or mismatched certificates |
| 7 | **Open Redirect Detection** | Malicious redirect chain identification |
| 8 | **URL Shortener Expansion** | Reveals true destination behind bit.ly, tinyurl, etc. |
| 9 | **IP-Based URL Detection** | Direct IP address links bypassing DNS |
| 10 | **WHOIS / DNS Record Analysis** | Registrar, nameserver, and record anomalies |

### Email Forensics — 25+ Methods

| # | Method | What It Catches |
|---|--------|-----------------|
| 1 | **SPF / DKIM / DMARC Validation** | Email origin authentication failures |
| 2 | **Header Spoofing Detection** | From ≠ Return-Path ≠ Reply-To mismatches |
| 3 | **Lookalike Domain Identification** | Brand impersonation in sender domains |
| 4 | **Urgency Language Detection** | "Act now", "account suspended", time-pressure triggers |
| 5 | **Threat / Intimidation Detection** | Legal threats, account deletion warnings |
| 6 | **Reward / Lottery Scam Detection** | Prize claims, inheritance offers |
| 7 | **Credential Harvesting Detection** | Login link patterns, fake portal redirects |
| 8 | **Social Engineering Detection** | Authority impersonation, reciprocity triggers |
| 9 | **Embedded URL Scanning** | Deep inspection of all links in email body |
| 10 | **Attachment Risk Assessment** | `.exe .ps1 .bat .vbs .iso .dmg` and 15+ dangerous extensions |

<br/>

---

## ◈ Risk Scoring

Each scan produces a 0–100 risk score computed from weighted indicator aggregation.

| Score Range | Level | Indicator | Recommended Action |
|:-----------:|-------|:---------:|--------------------|
| 0 – 20 | **Safe** | 🟢 | Low risk — proceed normally |
| 21 – 50 | **Suspicious** | 🟡 | Exercise caution — verify sender/domain |
| 51 – 80 | **High Risk** | 🟠 | Do not proceed — escalate for review |
| 81 – 100 | **Critical Threat** | 🔴 | Block immediately — report to SOC |

**Score drivers:** domain age, engine consensus, SSL validity, header anomalies, language pattern matches, redirect depth, TLD risk weight, and SPF/DKIM/DMARC failures.

<br/>

---

## ◈ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    FRONTEND  (HTML · CSS · JS)                   │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐    │
│  │Dashboard │  │  URL     │  │  Email   │  │ Batch Scanner  │    │
│  │          │  │ Analyzer │  │ Analyzer │  │ (100 URLs)     │    │
│  └──────────┘  └──────────┘  └──────────┘  └────────────────┘    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐    │
│  │ History  │  │ Threat   │  │   Geo    │  │  Settings      │    │
│  │          │  │  Intel   │  │ Analysis │  │                │    │
│  └──────────┘  └──────────┘  └──────────┘  └────────────────┘    │
└───────────────────────────────┬──────────────────────────────────┘
                                │  REST API
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                  BACKEND  (Flask · Python)                       │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  API Routes                                                 │ │
│  │  /api/scan/url  ·  /api/scan/email  ·  /api/scan/batch      │ │
│  │  /api/history   ·  /api/stats       ·  /api/threat-intel    │ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │                                      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Threat Detection Engine  (analyzer.py)                     │ │
│  │                                                             │ │
│  │  URL Analyzer      73+ engines · WHOIS · DNS · SSL          │ │
│  │  Email Analyzer    Headers · Auth · Language · Embeds       │ │
│  │  Pattern Engine    500+ signatures · Risk weighting         │ │
│  └────────────────────────┬────────────────────────────────────┘ │
└───────────────────────────┼──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                  DATABASE  (SQLite)                              │
│                                                                  │
│   scans  ·  findings  ·  breakdown  ·  threat_intel              │
└──────────────────────────────────────────────────────────────────┘
```

<br/>

---

## ◈ Dashboard Modules

| Module | Description |
|--------|-------------|
| **Dashboard** | Real-time metrics — total scans, threats detected, average risk, hourly volume charts, threat distribution donut, detection heatmap, 7-day risk trend, engine coverage gauge |
| **URL Analyzer** | Single URL deep scan with full indicator breakdown and per-engine verdict |
| **Email Analyzer** | Paste email content or raw headers for header forensics, auth validation, and language analysis |
| **Batch Scanner** | Scan up to 100 URLs simultaneously with progress tracking and CSV export |
| **Scan History** | Full searchable log of all scans with risk scores and finding summaries |
| **Threat Intelligence** | Live IOC feed — PayPal phish, Emotet, crypto scams; 7-day volume charts; source attribution (OpenPhish · VirusTotal · URLhaus) |
| **Geographic Analysis** | Threat origin world map, regional attack vector radar chart, hosting provider risk matrix with one-click blocking |
| **Settings** | API key management, theme toggle, notification preferences |

<br/>

---

## ◈ Quick Start

```bash
# 1. Clone
git clone https://github.com/parrysecurity/threatlens.git
cd threatlens

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run
python3 app.py
```

Open `http://localhost:5000`

| Demo Credential | Value |
|-----------------|-------|
| Email | `admin@threatscope.com` |
| Password | `admin123` |

> ⚠️ Change demo credentials before any internet-facing deployment.

<br/>

---

## ◈ Installation

### Prerequisites

```
Python  3.9+
pip
Git
```

### Step-by-step

```bash
# Clone
git clone https://github.com/parrysecurity/threatlens.git
cd threatlens

# Virtual environment
python3 -m venv venv
source venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Start
python3 app.py
# → Running on http://localhost:5000
```

### Dependencies

| Package | Version | Purpose |
|---------|:-------:|---------|
| `Flask` | 2.0+ | Web framework + REST API |
| `flask-cors` | 4.0+ | CORS header management |
| `flask-limiter` | 3.0+ | Rate limiting (50 req/hour) |
| `requests` | 2.28+ | External HTTP scanning |
| `beautifulsoup4` | 4.11+ | HTML parsing for embedded URL extraction |
| `python-whois` | 0.8+ | Domain WHOIS lookup |
| `tldextract` | 3.4+ | Reliable domain/TLD parsing |
| `dnspython` | 2.3+ | SPF/DKIM/DMARC DNS resolution |
| `chart.js` | 4.4+ | Frontend charts (CDN) |
| `fontawesome` | 6.5+ | UI icons (CDN) |

<br/>

---

## ◈ Configuration

### Environment variables

```bash
export DATABASE_PATH=/custom/path/threats.db
export FLASK_ENV=production
export SECRET_KEY=your-secret-key-here
```

### API keys *(optional — enhance detection coverage)*

Create `.env` in the repo root:

```bash
# Threat intelligence integrations
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here
GOOGLE_SAFE_BROWSING_KEY=your_key_here
```

> Without API keys, ThreatLens runs in **standalone mode** using built-in pattern recognition and DNS/WHOIS analysis. API keys expand engine coverage to the full 73+ count.

<br/>

---

## ◈ API Reference

Full endpoint documentation available at `http://localhost:5000/api-docs`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan/url` | Analyze a single URL |
| `POST` | `/api/scan/email` | Analyze email content or raw headers |
| `POST` | `/api/scan/batch` | Batch scan up to 100 URLs |
| `GET` | `/api/history` | Retrieve scan history |
| `GET` | `/api/scan/<id>` | Get full details for a specific scan |
| `GET` | `/api/stats` | Dashboard aggregate statistics |
| `GET` | `/api/export/csv` | Export scan history as CSV |
| `GET` | `/api/threat-intel` | Live IOC feed and campaign data |
| `GET` | `/api/health` | Platform health check |

### Example requests

```bash
# Scan a URL
curl -X POST http://localhost:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.xyz/login"}'

# Scan email content
curl -X POST http://localhost:5000/api/scan/email \
  -H "Content-Type: application/json" \
  -d '{"content": "From: support@paypa1.com\nSubject: Urgent: Verify your account"}'

# Batch scan
curl -X POST http://localhost:5000/api/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://url1.com", "https://url2.net", "https://url3.tk"]}'

# Export history
curl http://localhost:5000/api/export/csv > scan_history.csv
```

<br/>

---

## ◈ Performance

| Operation | Average Time |
|-----------|:-----------:|
| URL scan (single) | 1.4 s |
| Email scan | 2.1 s |
| Batch scan (20 URLs) | 28 s |
| History load | 0.3 s |
| Dashboard load | 0.8 s |

<br/>

---

## ◈ Security Model

| Control | Implementation |
|---------|---------------|
| **Input sanitization** | XSS prevention on all user-supplied fields |
| **SQL injection prevention** | Parameterized queries throughout the database layer |
| **Rate limiting** | 50 requests/hour per IP via `flask-limiter` |
| **Session management** | Secure cookie-based auth with remember-me support |
| **CSRF protection** | Token-based validation on all state-changing endpoints |
| **HTTPS compatibility** | SSL/TLS termination at reverse proxy (Nginx recommended) |
| **Secrets management** | All API keys loaded from `.env` — never hardcoded |

<br/>

---

## ◈ Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  threatlens:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - ./threats.db:/app/threats.db
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=change-this-in-production
```

```bash
# Build and run
docker build -t threatlens .
docker run -p 5000:5000 threatlens

# Or with Compose
docker-compose up -d
```

<br/>

---

## ◈ Troubleshooting

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `ModuleNotFoundError: flask` | Virtual env not active | `source venv/bin/activate && pip install -r requirements.txt` |
| `Address already in use :5000` | Port occupied | `sudo fuser -k 5000/tcp` or `python3 app.py --port 5001` |
| `Database disk image is malformed` | Corrupt SQLite file | `rm threats.db` — app auto-recreates on next start |
| `Permission denied: threats.db` | Wrong file permissions | `chmod 666 threats.db` |
| Blank dashboard on load | JS console error | Open DevTools → Console tab and check for missing CDN resources |
| Low detection coverage | No API keys set | Add keys to `.env` — see [Configuration](#-configuration) |

<br/>

---

## ◈ Project Structure

```
threatlens/
│
├── templates/
│   ├── index.html          ← Main dashboard SPA
│   ├── signin.html         ← Authentication page
│   └── signup.html         ← Registration page
│
├── static/
│   ├── style.css           ← UI styles (light/dark theme)
│   └── app.js              ← Frontend logic + Chart.js bindings
│
├── app.py                  ← Flask app: routes, auth, session management
├── analyzer.py             ← Threat detection engine (URL + email)
├── requirements.txt        ← Python dependencies
├── .env                    ← API keys (not committed)
├── .gitignore
└── README.md
```

<br/>

---

## ◈ Contributing

```bash
# 1. Fork → clone → branch
git checkout -b feature/dnp3-parser

# 2. Make changes; verify app starts cleanly
python3 app.py

# 3. Commit with a clear message
git commit -m "feat: add VirusTotal v3 API integration"

# 4. Push and open a Pull Request
git push origin feature/dnp3-parser
```

<br/>

---

## ◈ License

Distributed under the **MIT License** — see [`LICENSE`](LICENSE) for full terms.

<br/>

---

<div align="center">

Built with `Flask` · `Python` · `SQLite` · `Chart.js` · `VirusTotal` · `OpenPhish`

<br/>

*Protecting the digital world — one scan at a time. Leave a ⭐ if ThreatLens helped secure your team.*

</div>
