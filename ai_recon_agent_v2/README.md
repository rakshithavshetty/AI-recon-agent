# 🛡️ AI Reconnaissance Agent

An automated cybersecurity reconnaissance system that collects, processes, and intelligently analyzes information about target systems using AI-based analysis.

---

## 📋 Features

| Module | Description |
|---|---|
| **WHOIS Lookup** | Domain ownership, registrar, dates, nameservers |
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA records + SPF/DMARC check |
| **Subdomain Discovery** | crt.sh CT logs + DNS brute-force wordlist |
| **Port Scanner** | TCP connect scan on 50+ common ports with banner grabbing |
| **Tech Detection** | HTTP headers, cookies, body fingerprinting (30+ technologies) |
| **AI Analyzer** | Rule-based vulnerability detection (20 rules), risk scoring 0–100 |
| **Report Generator** | Full HTML + JSON security reports |

---

## 🚀 Quick Start

### 1. Clone / Create the project directory

```bash
cd ai_recon_agent
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the application

```bash
python app.py
```

### 4. Open in browser

```
http://localhost:5000
```

---

## 📁 Project Structure

```
ai_recon_agent/
├── app.py                        # Flask application entry point
├── requirements.txt
├── README.md
├── modules/
│   ├── __init__.py
│   ├── whois_lookup.py           # WHOIS data collection
│   ├── dns_enum.py               # DNS record enumeration
│   ├── subdomain_discovery.py    # Subdomain discovery (CT logs + brute-force)
│   ├── port_scanner.py           # TCP port scanner with banner grabbing
│   ├── tech_detection.py         # Technology fingerprinting
│   └── ai_analyzer.py            # AI-based rule engine & risk scoring
├── utils/
│   ├── __init__.py
│   ├── data_preprocessor.py      # Data cleaning, deduplication, structuring
│   └── report_generator.py       # HTML & JSON report generation
├── templates/
│   └── index.html                # Full frontend web UI
└── reports/                      # Generated reports (auto-created)
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/status/<session_id>` | Poll scan progress |
| `GET` | `/api/results/<session_id>` | Fetch full results JSON |
| `GET` | `/api/report/<session_id>` | Download HTML report |

### POST /api/scan

```json
{
  "target": "example.com",
  "modules": ["whois", "dns", "subdomains", "ports", "tech"]
}
```

---

## 🧠 AI Analysis Engine

The AI Analyzer applies **20 vulnerability rules** across categories:

- **Network Security** — Telnet, FTP, SMB, RDP, VNC exposure
- **Database Security** — MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, MSSQL
- **Web Security** — HTTPS, HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Application Security** — CMS detection, PHP version exposure
- **Domain Security** — Expiry monitoring, large attack surface

**Risk Scoring:**
- Critical findings: +40 points each
- High findings: +20 points each
- Medium findings: +10 points each
- Low findings: +5 points each
- Score is capped at 100

---

## ⚠️ Legal & Ethical Use

This tool is designed for:
- Authorized security assessments
- Penetration testing with written permission
- CTF challenges
- Educational purposes on systems you own

**Do NOT use against systems without explicit written authorization. Unauthorized reconnaissance may violate computer crime laws.**

---

## 📦 Dependencies

- `Flask` — Web framework
- `python-whois` — WHOIS lookups
- `dnspython` — DNS record enumeration
- `requests` — HTTP requests for tech detection and CT logs

---

## 🔧 Configuration

Edit `app.py` to change:
- `port=5000` — Server port
- `host="0.0.0.0"` — Bind address

Edit `modules/port_scanner.py` to customize:
- `COMMON_PORTS` — Add/remove ports to scan
- `timeout=1.5` — Socket timeout per port

Edit `modules/subdomain_discovery.py` to customize:
- `COMMON_SUBDOMAINS` — Wordlist for brute-force

---

## 📊 Sample Output

After a scan completes:
- **Risk Score**: 0–100
- **Risk Level**: Critical / High / Medium / Low / Info
- **Vulnerabilities**: Detailed list with ID, severity, description, recommendation
- **Attack Surface**: Open ports, subdomains, services
- **Security Posture**: HTTPS status, header compliance, CMS/CDN detection
- **Positive Findings**: What the target is doing right
- **HTML Report**: Downloadable, printable, shareable
