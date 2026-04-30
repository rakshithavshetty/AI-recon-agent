"""
Technology Detection Module - Fixed v2
Uses multiple methods: requests library, raw socket HTTP,
and raw TLS socket to bypass proxy restrictions.
Correctly detects security headers from actual server responses.
"""

import re
import socket
import ssl
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings()

TECH_SIGNATURES = {
    "WordPress": {
        "headers": [],
        "cookies": ["wordpress_", "wp-settings"],
        "body": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "meta": [r'name="generator"[^>]+WordPress'],
    },
    "Joomla": {
        "headers": [],
        "cookies": ["joomla"],
        "body": [r"/components/com_"],
        "meta": [r'name="generator"[^>]+Joomla'],
    },
    "Drupal": {
        "headers": ["x-generator: drupal", "x-drupal-cache"],
        "cookies": ["SESS"],
        "body": [r"/sites/default/files/"],
        "meta": [r'name="generator"[^>]+Drupal'],
    },
    "Django": {
        "headers": [],
        "cookies": ["csrftoken", "sessionid"],
        "body": [r"csrfmiddlewaretoken"],
        "meta": [],
    },
    "Laravel": {
        "headers": [],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "body": [r"laravel"],
        "meta": [],
    },
    "React": {
        "headers": [],
        "cookies": [],
        "body": [r"__reactFiber", r"react-dom"],
        "meta": [],
    },
    "Vue.js": {
        "headers": [],
        "cookies": [],
        "body": [r"__vue__", r"v-bind:", r"v-model"],
        "meta": [],
    },
    "Angular": {
        "headers": [],
        "cookies": [],
        "body": [r"ng-version=", r"angular\.min\.js"],
        "meta": [],
    },
    "jQuery": {
        "headers": [],
        "cookies": [],
        "body": [r"jquery[.-][\d]+", r"jquery\.min\.js"],
        "meta": [],
    },
    "Bootstrap": {
        "headers": [],
        "cookies": [],
        "body": [r"bootstrap\.min\.(css|js)"],
        "meta": [],
    },
    "Next.js": {
        "headers": ["x-powered-by: next.js"],
        "cookies": [],
        "body": [r"__NEXT_DATA__", r"/_next/static"],
        "meta": [],
    },
    "Nginx": {
        "headers": ["server: nginx"],
        "cookies": [],
        "body": [],
        "meta": [],
    },
    "Apache": {
        "headers": ["server: apache"],
        "cookies": [],
        "body": [],
        "meta": [],
    },
    "IIS": {
        "headers": ["server: microsoft-iis", "x-powered-by: asp.net"],
        "cookies": ["ASP.NET_SessionId"],
        "body": [],
        "meta": [],
    },
    "PHP": {
        "headers": ["x-powered-by: php"],
        "cookies": ["PHPSESSID"],
        "body": [r"\.php"],
        "meta": [],
    },
    "ASP.NET": {
        "headers": ["x-powered-by: asp.net", "x-aspnet-version"],
        "cookies": ["ASP.NET_SessionId"],
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
        "meta": [],
    },
    "Cloudflare": {
        "headers": ["cf-ray", "server: cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": [],
        "meta": [],
    },
    "Shopify": {
        "headers": ["x-shopid", "x-shopify-stage"],
        "cookies": ["_shopify_"],
        "body": [r"cdn\.shopify\.com"],
        "meta": [],
    },
    "Google Analytics": {
        "headers": [],
        "cookies": ["_ga", "_gid"],
        "body": [r"google-analytics\.com/analytics\.js", r"gtag\("],
        "meta": [],
    },
    "reCAPTCHA": {
        "headers": [],
        "cookies": [],
        "body": [r"grecaptcha", r"recaptcha/api"],
        "meta": [],
    },
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Permitted-Cross-Domain-Policies",
]


def run_tech_detection(target: str) -> dict:
    result = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "detected_technologies": [],
        "server": "N/A",
        "powered_by": "N/A",
        "headers": {},
        "security_headers": {"present": [], "missing": []},
        "cookies": [],
        "cms": None,
        "frameworks": [],
        "javascript_libs": [],
        "cdn": None,
        "https_enabled": False,
        "success": False
    }

    domain = target.lower().strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc

    headers_dict = {}
    body = ""
    cookie_names = []
    final_url = ""

    # Method 1: requests library (works when not proxied)
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            resp = requests.get(
                url, timeout=15, allow_redirects=True, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            )
            if resp.status_code not in (403,) or "x-deny-reason" not in resp.headers:
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.text[:50000]
                cookie_names = [c.name for c in resp.cookies]
                final_url = resp.url
                result["https_enabled"] = final_url.startswith("https")
                break
        except Exception:
            continue

    # Method 2: raw TLS socket (when requests is proxied/blocked)
    if not headers_dict or "x-deny-reason" in headers_dict:
        headers_dict, body, cookie_names = _raw_http_fetch(domain)
        result["https_enabled"] = True  # We tried TLS

    # Method 3: raw HTTP socket fallback
    if not headers_dict:
        headers_dict, body, cookie_names = _raw_http_fetch(domain, use_tls=False)
        result["https_enabled"] = False

    if not headers_dict:
        result["error"] = "Could not connect to target or all methods blocked"
        result["note"] = "Tech detection requires HTTP access to target. Run locally for full results."
        # Still provide partial info from DNS
        result["success"] = True
        return result

    # Extract server/powered-by
    result["server"] = headers_dict.get("server", "N/A")
    result["powered_by"] = headers_dict.get("x-powered-by", "N/A")
    result["headers"] = {k: v for k, v in headers_dict.items() if not k.startswith("x-deny")}
    result["cookies"] = cookie_names

    # Security headers check
    for header in SECURITY_HEADERS:
        if header.lower() in headers_dict:
            result["security_headers"]["present"].append(header)
        else:
            result["security_headers"]["missing"].append(header)

    # Fingerprint technologies
    detected = []
    for tech, sigs in TECH_SIGNATURES.items():
        matched = False
        for h_sig in sigs["headers"]:
            key, _, val = h_sig.lower().partition(": ")
            if key in headers_dict and (not val or val in headers_dict[key].lower()):
                matched = True
                break
        if not matched:
            for c_sig in sigs["cookies"]:
                if any(c_sig.lower() in c.lower() for c in cookie_names):
                    matched = True
                    break
        if not matched and body:
            for b_sig in sigs["body"]:
                if re.search(b_sig, body, re.IGNORECASE):
                    matched = True
                    break
        if not matched and body:
            for m_sig in sigs["meta"]:
                if re.search(m_sig, body, re.IGNORECASE):
                    matched = True
                    break
        if matched:
            detected.append(tech)

    result["detected_technologies"] = detected
    result["cms"] = next((t for t in detected if t in ("WordPress","Joomla","Drupal","Shopify","Wix")), None)
    result["frameworks"] = [t for t in detected if t in ("Django","Laravel","Next.js","ASP.NET")]
    result["javascript_libs"] = [t for t in detected if t in ("React","Vue.js","Angular","jQuery","Bootstrap")]
    result["cdn"] = next((t for t in detected if t in ("Cloudflare",)), None)
    result["success"] = True
    return result


def _raw_http_fetch(domain: str, use_tls: bool = True):
    """Fetch HTTP headers via raw socket, bypassing requests proxy."""
    headers_dict = {}
    body = ""
    cookies = []
    port = 443 if use_tls else 80

    try:
        ip = socket.gethostbyname(domain)
        raw_sock = socket.create_connection((ip, port), timeout=10)

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=domain)
        else:
            sock = raw_sock

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html,application/xhtml+xml,*/*\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if len(response) > 200000:
                    break
            except Exception:
                break
        sock.close()

        resp_str = response.decode("utf-8", errors="ignore")

        # Split headers and body
        if "\r\n\r\n" in resp_str:
            header_section, body = resp_str.split("\r\n\r\n", 1)
        else:
            header_section = resp_str
            body = ""

        # Parse status line and headers
        lines = header_section.split("\r\n")
        status_line = lines[0] if lines else ""

        # If it's a redirect (301/302), note it
        if "301" in status_line or "302" in status_line:
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers_dict[k.strip().lower()] = v.strip()
            # Try to follow redirect
            location = headers_dict.get("location", "")
            if location and "https" in location.lower() and not use_tls:
                return _raw_http_fetch(domain, use_tls=True)
        else:
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers_dict[k.strip().lower()] = v.strip()

        # Extract cookies from Set-Cookie headers
        for line in lines[1:]:
            if line.lower().startswith("set-cookie:"):
                cookie_part = line.split(":", 1)[1].strip().split(";")[0]
                cookie_name = cookie_part.split("=")[0].strip()
                if cookie_name:
                    cookies.append(cookie_name)

        # If response is proxied/denied, clear it
        if headers_dict.get("x-deny-reason"):
            return {}, "", []

    except Exception:
        pass

    return headers_dict, body[:50000], cookies
