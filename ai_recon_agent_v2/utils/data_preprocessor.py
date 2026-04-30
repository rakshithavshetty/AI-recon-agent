"""
Data Preprocessor Utility
Cleans, filters, deduplicates, and structures raw reconnaissance data
before AI analysis.
"""

from datetime import datetime


def preprocess_data(raw_data: dict) -> dict:
    """
    Clean and structure raw reconnaissance data.
    Returns a unified, analysis-ready dataset.
    """
    structured = {}

    # Process each module's data
    if "whois" in raw_data:
        structured["whois"] = _clean_whois(raw_data["whois"])

    if "dns" in raw_data:
        structured["dns"] = _clean_dns(raw_data["dns"])

    if "subdomains" in raw_data:
        structured["subdomains"] = _clean_subdomains(raw_data["subdomains"])

    if "ports" in raw_data:
        structured["ports"] = _clean_ports(raw_data["ports"])

    if "tech" in raw_data:
        structured["tech"] = _clean_tech(raw_data["tech"])

    structured["preprocessed_at"] = datetime.now().isoformat()
    structured["modules_run"] = list(raw_data.keys())

    return structured


def _clean_whois(data: dict) -> dict:
    """Normalize and clean WHOIS data."""
    cleaned = {
        "domain_name": _safe_str(data.get("domain_info", {}).get("domain_name")),
        "registrar": _safe_str(data.get("registrar_info", {}).get("registrar")),
        "registrant_org": _safe_str(data.get("domain_info", {}).get("registrant_org")),
        "registrant_country": _safe_str(data.get("domain_info", {}).get("registrant_country")),
        "creation_date": _safe_str(data.get("dates", {}).get("creation_date")),
        "expiration_date": _safe_str(data.get("dates", {}).get("expiration_date")),
        "updated_date": _safe_str(data.get("dates", {}).get("updated_date")),
        "nameservers": _dedup_list(data.get("nameservers", [])),
        "status": _dedup_list(data.get("status", [])),
        "success": data.get("success", False)
    }
    return cleaned


def _clean_dns(data: dict) -> dict:
    """Deduplicate and normalize DNS records."""
    records = data.get("records", {})
    cleaned = {
        "a_records": _dedup_list(records.get("A", [])),
        "aaaa_records": _dedup_list(records.get("AAAA", [])),
        "mx_records": records.get("MX", []),
        "ns_records": _dedup_list(records.get("NS", [])),
        "txt_records": _dedup_list([_safe_str(t) for t in records.get("TXT", [])]),
        "cname_records": _dedup_list(records.get("CNAME", [])),
        "soa_records": records.get("SOA", []),
        "resolved_ips": _dedup_list(data.get("resolved_ips", [])),
        "mail_servers": _dedup_list(data.get("mail_servers", [])),
        "name_servers": _dedup_list(data.get("name_servers", [])),
        "success": data.get("success", False)
    }
    # Flag potential misconfigurations
    cleaned["has_spf"] = any("v=spf1" in t for t in cleaned["txt_records"])
    cleaned["has_dmarc"] = any("v=DMARC1" in t for t in cleaned["txt_records"])
    cleaned["has_dkim_hint"] = any("v=DKIM1" in t for t in cleaned["txt_records"])
    return cleaned


def _clean_subdomains(data: dict) -> dict:
    """Deduplicate and sort subdomains."""
    all_subs = _dedup_list(data.get("discovered_subdomains", []))
    return {
        "discovered_subdomains": sorted(all_subs),
        "total_found": len(all_subs),
        "ct_log_count": len(data.get("ct_log_subdomains", [])),
        "bruteforce_count": len(data.get("bruteforce_subdomains", [])),
        "success": data.get("success", False)
    }


def _clean_ports(data: dict) -> dict:
    """Deduplicate and sort port scan results."""
    open_ports = data.get("open_ports", [])
    # Deduplicate by port number
    seen_ports = set()
    unique_ports = []
    for p in open_ports:
        if p["port"] not in seen_ports:
            seen_ports.add(p["port"])
            unique_ports.append(p)

    unique_ports.sort(key=lambda x: x["port"])

    return {
        "resolved_ip": data.get("resolved_ip"),
        "open_ports": unique_ports,
        "open_port_numbers": [p["port"] for p in unique_ports],
        "services": {str(p["port"]): p["service"] for p in unique_ports},
        "risk_ports": data.get("risk_ports", []),
        "total_open": len(unique_ports),
        "total_scanned": data.get("total_scanned", 0),
        "success": data.get("success", False)
    }


def _clean_tech(data: dict) -> dict:
    """Clean and deduplicate technology detection results."""
    return {
        "detected_technologies": _dedup_list(data.get("detected_technologies", [])),
        "server": data.get("server", "N/A"),
        "powered_by": data.get("powered_by", "N/A"),
        "cms": data.get("cms"),
        "frameworks": _dedup_list(data.get("frameworks", [])),
        "javascript_libs": _dedup_list(data.get("javascript_libs", [])),
        "cdn": data.get("cdn"),
        "https_enabled": data.get("https_enabled", False),
        "security_headers": data.get("security_headers", {"present": [], "missing": []}),
        "cookies": _dedup_list(data.get("cookies", [])),
        "success": data.get("success", False)
    }


def _safe_str(value) -> str:
    """Safely convert any value to string."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return value[0] if value else "N/A"
    return str(value).strip() or "N/A"


def _dedup_list(lst: list) -> list:
    """Remove duplicates while preserving order."""
    seen = set()
    result = []
    for item in lst:
        key = str(item).lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result
