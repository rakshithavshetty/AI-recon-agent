"""
DNS Enumeration Module - Fixed v2
Enumerates DNS records with explicit nameserver configuration,
longer timeouts, and safe per-record error handling.
"""

import socket
from datetime import datetime


def run_dns_enum(target: str) -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "records": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": [], "SOA": []},
        "resolved_ips": [],
        "mail_servers": [],
        "name_servers": [],
        "success": False
    }

    domain = target.lower().strip().lstrip("www.")

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        resolver.timeout = 5
        resolver.lifetime = 10

        # A records
        try:
            for rdata in resolver.resolve(domain, "A"):
                ip = str(rdata.address)
                result["records"]["A"].append(ip)
                result["resolved_ips"].append(ip)
        except Exception:
            # Fallback: use socket
            try:
                infos = socket.getaddrinfo(domain, None)
                for info in infos:
                    ip = info[4][0]
                    if "." in ip and ip not in result["records"]["A"]:
                        result["records"]["A"].append(ip)
                        result["resolved_ips"].append(ip)
            except Exception:
                pass

        # AAAA records
        try:
            for rdata in resolver.resolve(domain, "AAAA"):
                result["records"]["AAAA"].append(str(rdata.address))
        except Exception:
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for info in infos:
                    ip = info[4][0]
                    if ":" in ip and ip not in result["records"]["AAAA"]:
                        result["records"]["AAAA"].append(ip)
            except Exception:
                pass

        # MX records
        try:
            for rdata in resolver.resolve(domain, "MX"):
                mx = {"priority": rdata.preference, "exchange": str(rdata.exchange).rstrip(".")}
                result["records"]["MX"].append(mx)
                result["mail_servers"].append(mx["exchange"])
        except Exception:
            pass

        # NS records
        try:
            for rdata in resolver.resolve(domain, "NS"):
                ns = str(rdata.target).rstrip(".")
                result["records"]["NS"].append(ns)
                result["name_servers"].append(ns)
        except Exception:
            pass

        # TXT records
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = " ".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                result["records"]["TXT"].append(txt)
        except Exception:
            pass

        # DMARC TXT
        try:
            for rdata in resolver.resolve(f"_dmarc.{domain}", "TXT"):
                txt = " ".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if txt not in result["records"]["TXT"]:
                    result["records"]["TXT"].append(txt)
        except Exception:
            pass

        # CNAME records
        try:
            for rdata in resolver.resolve(domain, "CNAME"):
                result["records"]["CNAME"].append(str(rdata.target).rstrip("."))
        except Exception:
            pass

        # SOA records
        try:
            for rdata in resolver.resolve(domain, "SOA"):
                result["records"]["SOA"].append({
                    "mname": str(rdata.mname).rstrip("."),
                    "rname": str(rdata.rname).rstrip("."),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum
                })
        except Exception:
            pass

        result["success"] = True

    except ImportError:
        # Pure socket fallback when dnspython not available
        try:
            infos = socket.getaddrinfo(domain, None)
            for info in infos:
                ip = info[4][0]
                if "." in ip and ip not in result["records"]["A"]:
                    result["records"]["A"].append(ip)
                    result["resolved_ips"].append(ip)
            result["success"] = True
            result["note"] = "dnspython not installed; only A records via socket"
        except Exception as e:
            result["error"] = str(e)

    except Exception as e:
        result["error"] = str(e)
        # Still try socket fallback
        try:
            ip = socket.gethostbyname(domain)
            result["records"]["A"].append(ip)
            result["resolved_ips"].append(ip)
            result["success"] = True
        except Exception:
            pass

    return result
