"""
Port Scanner Module - Fixed v2
Fixes: hostname resolution, timeout tuning, banner grabbing,
and correct result structure.
"""

import socket
import ssl
import concurrent.futures
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2181: "ZooKeeper", 3000: "Node/Grafana", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "SonarQube", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "ES-Transport", 27017: "MongoDB",
}

RISK_LEVEL = {
    23: "critical", 4444: "critical", 6379: "critical",
    9200: "critical", 27017: "critical",
    21: "high", 25: "high", 135: "high", 139: "high", 445: "high",
    1433: "high", 3306: "high", 3389: "high", 5432: "high",
    5900: "high", 1521: "high",
    8080: "medium", 8888: "medium", 5984: "medium",
}


def run_port_scan(target: str, ports: list = None,
                  timeout: float = 2.0, max_workers: int = 80) -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "resolved_ip": None,
        "open_ports": [],
        "closed_ports_count": 0,
        "services": {},
        "risk_ports": [],
        "total_scanned": 0,
        "success": False
    }

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Resolve hostname — critical fix: resolve once, reuse
    try:
        ip = socket.gethostbyname(target.lower().strip())
        result["resolved_ip"] = ip
    except socket.gaierror as e:
        # Try stripping www.
        try:
            clean = target.lower().strip().lstrip("www.")
            ip = socket.gethostbyname(clean)
            result["resolved_ip"] = ip
        except socket.gaierror:
            result["error"] = f"Cannot resolve {target}: {e}"
            result["success"] = False
            return result

    open_ports = []
    closed_count = 0

    def check_port(port: int):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                banner = _grab_banner(sock, ip, port, timeout)
                return {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "Unknown"),
                    "state": "open",
                    "banner": banner,
                    "risk": RISK_LEVEL.get(port, "low")
                }
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures, timeout=60):
            try:
                res = future.result()
            except Exception:
                res = None
            if res:
                open_ports.append(res)
            else:
                closed_count += 1

    open_ports.sort(key=lambda x: x["port"])

    result["open_ports"] = open_ports
    result["closed_ports_count"] = closed_count
    result["total_scanned"] = len(ports)
    result["services"] = {p["port"]: p["service"] for p in open_ports}
    result["risk_ports"] = [p for p in open_ports if p["risk"] in ("high", "critical")]
    result["success"] = True
    return result


def _grab_banner(sock: socket.socket, ip: str, port: int, timeout: float) -> str:
    """Safely grab a service banner."""
    try:
        sock.settimeout(min(timeout, 2.0))
        if port in (80, 8080, 8000, 3000, 5000, 9000, 9090):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        elif port in (443, 8443):
            # Try TLS upgrade for banner
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(sock, server_hostname=ip)
                tls_sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                banner = tls_sock.recv(512).decode("utf-8", errors="ignore").strip()
                return banner.split("\n")[0][:150] if banner else ""
            except Exception:
                pass
        else:
            sock.send(b"\r\n")

        data = sock.recv(512)
        if data:
            decoded = data.decode("utf-8", errors="ignore").strip()
            return decoded.split("\n")[0][:150]
        return ""
    except Exception:
        return ""
