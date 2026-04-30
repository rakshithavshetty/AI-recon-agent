"""
AI Analysis Module
Applies rule-based and pattern analysis to reconnaissance data.
Produces risk assessments, vulnerability indicators, and recommendations.
"""

from datetime import datetime


# Risk weights for scoring
RISK_WEIGHTS = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 1
}

# Vulnerability rule definitions
VULN_RULES = [
    {
        "id": "V001",
        "name": "Telnet Service Exposed",
        "severity": "critical",
        "check": lambda data: _port_open(data, 23),
        "description": "Telnet transmits data in plaintext including credentials.",
        "recommendation": "Disable Telnet. Use SSH (port 22) instead."
    },
    {
        "id": "V002",
        "name": "FTP Service Exposed",
        "severity": "high",
        "check": lambda data: _port_open(data, 21),
        "description": "FTP transmits credentials and data in plaintext.",
        "recommendation": "Replace FTP with SFTP or FTPS. Restrict access by IP."
    },
    {
        "id": "V003",
        "name": "SMB Service Exposed",
        "severity": "high",
        "check": lambda data: _port_open(data, 445),
        "description": "SMB (port 445) has been exploited by WannaCry and similar ransomware.",
        "recommendation": "Block SMB from internet. Apply all patches. Disable SMBv1."
    },
    {
        "id": "V004",
        "name": "RDP Service Exposed",
        "severity": "high",
        "check": lambda data: _port_open(data, 3389),
        "description": "RDP exposed to the internet is a common brute-force target.",
        "recommendation": "Use VPN before RDP. Enable NLA. Rate-limit login attempts."
    },
    {
        "id": "V005",
        "name": "Database Port Exposed (MySQL)",
        "severity": "high",
        "check": lambda data: _port_open(data, 3306),
        "description": "MySQL exposed to internet allows direct attack attempts.",
        "recommendation": "Bind MySQL to localhost (127.0.0.1). Use a firewall."
    },
    {
        "id": "V006",
        "name": "Database Port Exposed (PostgreSQL)",
        "severity": "high",
        "check": lambda data: _port_open(data, 5432),
        "description": "PostgreSQL exposed to internet allows direct attack attempts.",
        "recommendation": "Bind PostgreSQL to localhost. Use pg_hba.conf to restrict access."
    },
    {
        "id": "V007",
        "name": "MongoDB Exposed",
        "severity": "critical",
        "check": lambda data: _port_open(data, 27017),
        "description": "MongoDB with no auth has led to mass data breaches.",
        "recommendation": "Enable MongoDB authentication. Bind to localhost only."
    },
    {
        "id": "V008",
        "name": "Redis Exposed",
        "severity": "critical",
        "check": lambda data: _port_open(data, 6379),
        "description": "Redis with no auth is exploitable for data theft and RCE.",
        "recommendation": "Set Redis password. Bind to localhost. Use firewall rules."
    },
    {
        "id": "V009",
        "name": "Elasticsearch Exposed",
        "severity": "critical",
        "check": lambda data: _port_open(data, 9200),
        "description": "Unauthenticated Elasticsearch leads to data exposure.",
        "recommendation": "Enable X-Pack security. Bind to private network. Use firewall."
    },
    {
        "id": "V010",
        "name": "Missing HTTPS",
        "severity": "high",
        "check": lambda data: not data.get("tech", {}).get("https_enabled", True),
        "description": "Site does not redirect to HTTPS, allowing MITM attacks.",
        "recommendation": "Obtain a TLS certificate (Let's Encrypt). Redirect all HTTP to HTTPS."
    },
    {
        "id": "V011",
        "name": "Missing HSTS Header",
        "severity": "medium",
        "check": lambda data: _missing_sec_header(data, "Strict-Transport-Security"),
        "description": "Without HSTS, browsers can be forced to downgrade to HTTP.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    {
        "id": "V012",
        "name": "Missing CSP Header",
        "severity": "medium",
        "check": lambda data: _missing_sec_header(data, "Content-Security-Policy"),
        "description": "Without CSP, the site is vulnerable to XSS attacks.",
        "recommendation": "Implement a Content-Security-Policy header to restrict resource origins."
    },
    {
        "id": "V013",
        "name": "Missing X-Frame-Options",
        "severity": "medium",
        "check": lambda data: _missing_sec_header(data, "X-Frame-Options"),
        "description": "Without X-Frame-Options, the site may be clickjacked.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    {
        "id": "V014",
        "name": "Missing X-Content-Type-Options",
        "severity": "low",
        "check": lambda data: _missing_sec_header(data, "X-Content-Type-Options"),
        "description": "MIME-type sniffing can be used for attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    {
        "id": "V015",
        "name": "Outdated/Exposed CMS",
        "severity": "medium",
        "check": lambda data: bool(data.get("tech", {}).get("cms")),
        "description": "CMS detected. Outdated CMS versions have known vulnerabilities.",
        "recommendation": "Keep CMS and plugins updated. Hide CMS version from public. Use WAF."
    },
    {
        "id": "V016",
        "name": "Large Attack Surface (Many Subdomains)",
        "severity": "medium",
        "check": lambda data: len(data.get("subdomains", {}).get("discovered_subdomains", [])) > 20,
        "description": "Many subdomains increase the attack surface.",
        "recommendation": "Review and remove unused subdomains. Monitor for subdomain takeover."
    },
    {
        "id": "V017",
        "name": "Domain Expiring Soon",
        "severity": "medium",
        "check": lambda data: _domain_expiring_soon(data),
        "description": "Domain expiry risk may allow an attacker to register the domain.",
        "recommendation": "Renew domain registration. Enable auto-renew."
    },
    {
        "id": "V018",
        "name": "VNC Service Exposed",
        "severity": "high",
        "check": lambda data: _port_open(data, 5900),
        "description": "VNC provides graphical remote access and may have weak authentication.",
        "recommendation": "Disable VNC or restrict by IP. Use encrypted tunnels (VPN/SSH)."
    },
    {
        "id": "V019",
        "name": "MSSQL Exposed",
        "severity": "high",
        "check": lambda data: _port_open(data, 1433),
        "description": "MSSQL exposed allows brute-force and SQL injection attempts.",
        "recommendation": "Restrict MSSQL to private network. Use Windows Firewall rules."
    },
    {
        "id": "V020",
        "name": "PHP Detected",
        "severity": "low",
        "check": lambda data: "PHP" in data.get("tech", {}).get("detected_technologies", []),
        "description": "PHP version exposed may reveal known vulnerabilities.",
        "recommendation": "Hide PHP version (expose_php = Off). Keep PHP updated."
    },
]


def analyze_results(structured_data: dict, target: str) -> dict:
    """
    AI-based analysis: apply all vulnerability rules, calculate risk score,
    classify overall risk, and produce recommendations.
    """
    analysis = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": [],
        "risk_score": 0,
        "risk_level": "low",
        "risk_breakdown": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "security_posture": {},
        "recommendations": [],
        "attack_surface_summary": {},
        "technology_risk": [],
        "positive_findings": []
    }

    # Run all vulnerability rules
    for rule in VULN_RULES:
        try:
            triggered = rule["check"](structured_data)
            if triggered:
                vuln = {
                    "id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommendation": rule["recommendation"]
                }
                analysis["vulnerabilities"].append(vuln)
                analysis["risk_breakdown"][rule["severity"]] += 1
        except Exception:
            pass

    # Calculate risk score
    score = sum(
        RISK_WEIGHTS.get(v["severity"], 0)
        for v in analysis["vulnerabilities"]
    )
    analysis["risk_score"] = min(score, 100)

    # Determine overall risk level
    rb = analysis["risk_breakdown"]
    if rb["critical"] > 0:
        analysis["risk_level"] = "critical"
    elif rb["high"] > 0:
        analysis["risk_level"] = "high"
    elif rb["medium"] > 0:
        analysis["risk_level"] = "medium"
    elif rb["low"] > 0:
        analysis["risk_level"] = "low"
    else:
        analysis["risk_level"] = "info"

    # Security posture analysis
    tech = structured_data.get("tech", {})
    sec_headers = tech.get("security_headers", {})
    present = sec_headers.get("present", [])
    missing = sec_headers.get("missing", [])

    analysis["security_posture"] = {
        "https_enabled": tech.get("https_enabled", False),
        "security_headers_score": f"{len(present)}/{len(present)+len(missing)}",
        "missing_headers": missing,
        "cms_detected": tech.get("cms"),
        "cdn_protected": bool(tech.get("cdn")),
    }

    # Attack surface summary
    ports = structured_data.get("ports", {})
    subs = structured_data.get("subdomains", {})
    dns = structured_data.get("dns", {})

    analysis["attack_surface_summary"] = {
        "open_ports": len(ports.get("open_ports", [])),
        "high_risk_ports": len(ports.get("risk_ports", [])),
        "subdomains_found": subs.get("total_found", 0),
        "mail_servers": len(dns.get("mail_servers", [])),
        "name_servers": len(dns.get("name_servers", [])),
        "exposed_services": [p["service"] for p in ports.get("open_ports", [])],
    }

    # Positive findings
    positives = []
    if tech.get("https_enabled"):
        positives.append("HTTPS is enabled")
    if "Strict-Transport-Security" in present:
        positives.append("HSTS header present")
    if "Content-Security-Policy" in present:
        positives.append("CSP header present")
    if tech.get("cdn"):
        positives.append(f"CDN protection via {tech['cdn']}")
    analysis["positive_findings"] = positives

    # Technology risk assessment
    risky_techs = {
        "WordPress": "Frequent plugin vulnerabilities. Keep updated.",
        "PHP": "Ensure PHP is updated and version not exposed.",
        "ASP.NET": "Ensure .NET framework is patched.",
    }
    detected = tech.get("detected_technologies", [])
    analysis["technology_risk"] = [
        {"technology": t, "risk_note": risky_techs[t]}
        for t in detected if t in risky_techs
    ]

    # Top recommendations (deduplicated from vulnerabilities)
    analysis["recommendations"] = [
        {"priority": i + 1, "action": v["recommendation"], "for": v["name"]}
        for i, v in enumerate(
            sorted(analysis["vulnerabilities"],
                   key=lambda x: RISK_WEIGHTS.get(x["severity"], 0),
                   reverse=True)[:10]
        )
    ]

    return analysis


# ---- Helper functions ----

def _port_open(data: dict, port: int) -> bool:
    ports_data = data.get("ports", {})
    open_ports = ports_data.get("open_ports", [])
    return any(p["port"] == port for p in open_ports)


def _missing_sec_header(data: dict, header: str) -> bool:
    tech = data.get("tech", {})
    missing = tech.get("security_headers", {}).get("missing", [])
    return header in missing


def _domain_expiring_soon(data: dict) -> bool:
    """Check if domain expires within 60 days."""
    try:
        from datetime import datetime, timezone
        exp = data.get("whois", {}).get("dates", {}).get("expiration_date", "N/A")
        if exp == "N/A":
            return False
        # Parse ISO date
        exp_date = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = (exp_date - now).days
        return diff < 60
    except Exception:
        return False
