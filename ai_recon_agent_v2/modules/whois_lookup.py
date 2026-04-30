"""
WHOIS Lookup Module - Fixed v2
Uses RDAP (REST-based WHOIS over HTTPS) as primary method.
Falls back to raw socket WHOIS, then DNS-derived info.
"""

import socket
import re
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "io":  "https://rdap.nic.io/",
    "co":  "https://rdap.nic.co/",
    "in":  "https://rdap.registry.in/",
    "uk":  "https://rdap.nominet.uk/uk/",
}

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "co":  "whois.nic.co",
    "in":  "whois.registry.in",
    "uk":  "whois.nic.uk",
}

NS_REGISTRAR_HINTS = {
    "cloudflare": "Cloudflare",
    "awsdns": "Amazon Route 53",
    "google": "Google Domains / Squarespace",
    "azure-dns": "Microsoft Azure DNS",
    "godaddy": "GoDaddy",
    "namecheap": "Namecheap",
    "domaincontrol": "GoDaddy",
    "registrar-servers": "Namecheap",
    "name-services": "Dynadot",
    "nsone": "NS1",
    "ultradns": "UltraDNS",
    "dnsimple": "DNSimple",
    "hover": "Hover",
    "gandi": "Gandi",
}


def run_whois(target: str) -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "domain_info": {"domain_name": "N/A", "registrant_org": "N/A",
                        "registrant_country": "N/A", "registrant_email": "N/A"},
        "registrar_info": {"registrar": "N/A", "whois_server": "N/A"},
        "dates": {"creation_date": "N/A", "expiration_date": "N/A", "updated_date": "N/A"},
        "nameservers": [],
        "status": [],
        "raw": "",
        "success": False,
        "method": "none"
    }

    domain = target.lower().strip().lstrip("www.")

    # Method 1: RDAP
    result = _try_rdap(domain, result)
    if result.get("success"):
        return result

    # Method 2: python-whois
    result = _try_python_whois(domain, result)
    if result.get("success"):
        return result

    # Method 3: raw socket port 43
    result = _try_raw_socket_whois(domain, result)
    if result.get("success"):
        return result

    # Method 4: DNS fallback - always gives partial useful data
    return _dns_fallback(domain, result)


def _try_rdap(domain, result):
    try:
        tld = domain.split(".")[-1]
        urls = [
            RDAP_SERVERS.get(tld, "") + f"domain/{domain}",
            f"https://rdap.org/domain/{domain}",
            f"https://rdap.iana.org/domain/{domain}",
        ]
        for url in urls:
            if not url.startswith("http"):
                continue
            try:
                r = requests.get(url, timeout=10, verify=False,
                                 headers={"Accept": "application/rdap+json",
                                          "User-Agent": "AI-Recon-Agent/2.0"})
                if r.status_code == 200:
                    data = r.json()
                    _parse_rdap_into(data, result)
                    result["success"] = True
                    result["method"] = "rdap"
                    return result
            except Exception:
                continue
    except Exception:
        pass
    return result


def _parse_rdap_into(data, result):
    result["domain_info"]["domain_name"] = data.get("ldhName", "N/A")
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
        fn = next((f[3] for f in vcard if f[0] == "fn"), "N/A")
        if "registrar" in roles:
            result["registrar_info"]["registrar"] = fn
        if "registrant" in roles:
            result["domain_info"]["registrant_org"] = fn
            country = next((f[3] for f in vcard if f[0] == "adr"), None)
            if isinstance(country, list) and len(country) >= 7:
                result["domain_info"]["registrant_country"] = country[6] or "N/A"
            email = next((f[3] for f in vcard if f[0] == "email"), "N/A")
            result["domain_info"]["registrant_email"] = email
    for ev in data.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "N/A")
        if action == "registration":
            result["dates"]["creation_date"] = date[:10]
        elif action == "expiration":
            result["dates"]["expiration_date"] = date[:10]
        elif "changed" in action:
            result["dates"]["updated_date"] = date[:10]
    result["nameservers"] = [ns.get("ldhName", "").lower() for ns in data.get("nameservers", [])]
    result["status"] = data.get("status", [])


def _try_python_whois(domain, result):
    try:
        import whois as pw
        w = pw.whois(domain)
        if w and w.domain_name:
            result["domain_info"] = {
                "domain_name": _norm(w.domain_name),
                "registrant_org": _norm(getattr(w, "org", None)),
                "registrant_country": _norm(getattr(w, "country", None)),
                "registrant_email": _norm(getattr(w, "emails", None)),
            }
            result["registrar_info"] = {
                "registrar": _norm(w.registrar),
                "whois_server": _norm(getattr(w, "whois_server", None)),
            }
            result["dates"] = {
                "creation_date": _fdate(w.creation_date),
                "expiration_date": _fdate(w.expiration_date),
                "updated_date": _fdate(getattr(w, "updated_date", None)),
            }
            result["nameservers"] = ([n.lower() for n in w.name_servers]
                                     if isinstance(w.name_servers, list)
                                     else ([w.name_servers.lower()] if w.name_servers else []))
            result["status"] = (w.status if isinstance(w.status, list)
                                else ([w.status] if w.status else []))
            result["raw"] = str(getattr(w, "text", ""))[:2000]
            result["success"] = True
            result["method"] = "python-whois"
    except Exception:
        pass
    return result


def _try_raw_socket_whois(domain, result):
    tld = domain.split(".")[-1]
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")
    try:
        with socket.create_connection((server, 43), timeout=8) as s:
            s.send(f"{domain}\r\n".encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
        raw_text = raw.decode("utf-8", errors="ignore")
        result["raw"] = raw_text[:3000]

        def ex(pat):
            m = re.search(pat, raw_text, re.IGNORECASE)
            return m.group(1).strip() if m else "N/A"

        result["registrar_info"]["registrar"] = ex(r"Registrar:\s*(.+)")
        result["registrar_info"]["whois_server"] = ex(r"Registrar WHOIS Server:\s*(.+)")
        result["domain_info"]["domain_name"] = ex(r"Domain Name:\s*(.+)")
        result["domain_info"]["registrant_org"] = ex(r"Registrant Organization:\s*(.+)")
        result["domain_info"]["registrant_country"] = ex(r"Registrant Country:\s*(.+)")
        result["domain_info"]["registrant_email"] = ex(r"Registrant Email:\s*(.+)")
        result["dates"]["creation_date"] = ex(r"Creation Date:\s*(.+)").split("T")[0]
        result["dates"]["expiration_date"] = ex(r"Registry Expiry Date:\s*(.+)").split("T")[0]
        result["dates"]["updated_date"] = ex(r"Updated Date:\s*(.+)").split("T")[0]
        result["nameservers"] = [n.strip().lower() for n in
                                 re.findall(r"Name Server:\s*(.+)", raw_text, re.IGNORECASE)]
        result["status"] = [s.strip() for s in
                            re.findall(r"Domain Status:\s*(.+)", raw_text, re.IGNORECASE)]
        if result["domain_info"]["domain_name"] != "N/A":
            result["success"] = True
            result["method"] = "raw-socket-whois"
    except Exception:
        pass
    return result


def _dns_fallback(domain, result):
    """Derive registrar and info from DNS when WHOIS is unavailable."""
    try:
        import dns.resolver
        r = dns.resolver.Resolver()
        r.nameservers = ["8.8.8.8", "1.1.1.1"]
        r.timeout = 3
        r.lifetime = 6

        ns_list = []
        try:
            ns_ans = r.resolve(domain, "NS")
            ns_list = [str(ns).rstrip(".").lower() for ns in ns_ans]
            result["nameservers"] = ns_list
        except Exception:
            pass

        # Guess registrar from NS
        registrar = "Unknown"
        for ns in ns_list:
            for hint, name in NS_REGISTRAR_HINTS.items():
                if hint in ns:
                    registrar = name
                    break
        result["registrar_info"]["registrar"] = f"{registrar} (inferred from nameservers)"

        # Resolved IP as domain info
        try:
            ip = socket.gethostbyname(domain)
            result["domain_info"]["domain_name"] = domain.upper()
            result["domain_info"]["resolved_ip"] = ip
        except Exception:
            result["domain_info"]["domain_name"] = domain.upper()

        result["dates"] = {
            "creation_date": "Unavailable — run locally for full WHOIS",
            "expiration_date": "Unavailable",
            "updated_date": "Unavailable"
        }
        result["success"] = True
        result["method"] = "dns-fallback"
        result["note"] = (
            "Full WHOIS unavailable in this environment. "
            "Running locally will fetch complete registration data."
        )
    except Exception as e:
        result["error"] = str(e)
        result["success"] = False
    return result


def _norm(v):
    if v is None:
        return "N/A"
    if isinstance(v, list):
        return str(v[0]).strip() if v else "N/A"
    return str(v).strip() or "N/A"


def _fdate(v):
    if v is None:
        return "N/A"
    if isinstance(v, list):
        v = v[0]
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d")
    return str(v).split("T")[0] if v else "N/A"
