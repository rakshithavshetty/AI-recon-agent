"""
Subdomain Discovery Module - Fixed v2
Expanded wordlist, parallel DNS brute-force, crt.sh with retry,
and robust fallback when crt.sh is unreachable.
"""

import socket
import concurrent.futures
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

# Expanded wordlist - 120 common subdomains
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "blog", "shop", "store", "dev", "staging", "test", "api", "admin",
    "portal", "vpn", "cdn", "static", "media", "img", "images", "video",
    "m", "mobile", "app", "secure", "login", "auth", "sso", "oauth",
    "ns1", "ns2", "mx", "mx1", "mx2", "mail2", "smtp2",
    "intranet", "internal", "corp", "support", "help", "docs", "wiki",
    "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
    "monitor", "grafana", "kibana", "elastic", "prometheus", "metrics",
    "s3", "files", "backup", "data", "db", "database", "mysql", "postgres",
    "redis", "cache", "queue", "worker", "jobs", "scheduler",
    "beta", "alpha", "demo", "sandbox", "uat", "qa", "prod", "production",
    "panel", "cpanel", "plesk", "whm", "webmin", "phpmyadmin",
    "search", "news", "events", "forum", "community",
    "assets", "download", "uploads", "status", "health", "ping",
    "api2", "api-v2", "v2", "v1", "old", "new", "legacy",
    "crm", "erp", "hr", "finance", "accounting", "pay", "billing",
    "cloud", "ws", "wss", "socket", "push", "notifications",
    "smtp3", "mail3", "imap2", "pop3",
    "test2", "dev2", "stage", "preprod", "preview",
    "admin2", "adminpanel", "backoffice", "backend", "frontend",
    "dashboard", "console", "manage", "management", "cms",
    "media2", "static2", "cdn2", "assets2",
    "vpn2", "remote2", "rdp", "ssh",
    "exchange", "owa", "autodiscover",
    "ftp2", "sftp", "ftps",
    "shop2", "store2", "cart", "checkout", "payment",
    "api3", "rest", "graphql", "grpc",
    "log", "logs", "logging", "audit",
    "proxy", "gateway", "lb", "loadbalancer",
    "k8s", "kube", "kubernetes", "docker", "registry",
    "sonar", "sonarqube", "nexus", "artifactory",
    "mail4", "relay", "bounce",
    "test3", "testing", "qa2", "uat2",
]


def run_subdomain_discovery(target: str, max_workers: int = 30) -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "discovered_subdomains": [],
        "ct_log_subdomains": [],
        "bruteforce_subdomains": [],
        "total_found": 0,
        "success": False
    }

    base_domain = target.lower().strip()
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    # Method 1: Certificate Transparency logs (crt.sh)
    ct_subs = _query_crt_sh(base_domain)
    result["ct_log_subdomains"] = ct_subs

    # Method 2: DNS brute-force (always works)
    bf_subs = _dns_bruteforce(base_domain, max_workers)
    result["bruteforce_subdomains"] = bf_subs

    # Merge + deduplicate
    all_subs = list(set(ct_subs + bf_subs))
    all_subs.sort()
    result["discovered_subdomains"] = all_subs
    result["total_found"] = len(all_subs)
    result["success"] = True
    return result


def _query_crt_sh(domain: str) -> list:
    """Query crt.sh with retries and multiple URL formats."""
    subdomains = []
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q={domain}&output=json",
    ]
    for url in urls:
        try:
            resp = requests.get(url, timeout=20, verify=False,
                                headers={"User-Agent": "AI-Recon-Agent/2.0"})
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name_val = entry.get("name_value", "")
                    for sub in name_val.split("\n"):
                        sub = sub.strip().lower().lstrip("*.")
                        if (sub.endswith(f".{domain}") or sub == domain) and sub not in subdomains:
                            subdomains.append(sub)
                if subdomains:
                    break
        except Exception:
            continue
    return subdomains


def _check_subdomain(args) -> dict | None:
    sub, base_domain = args
    full = f"{sub}.{base_domain}"
    try:
        ip = socket.gethostbyname(full)
        return {"subdomain": full, "ip": ip}
    except socket.gaierror:
        return None


def _dns_bruteforce(domain: str, max_workers: int) -> list:
    """Parallel DNS brute-force using expanded wordlist."""
    found = []
    args = [(sub, domain) for sub in COMMON_SUBDOMAINS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for result in executor.map(_check_subdomain, args):
            if result:
                found.append(result["subdomain"])
    return found
