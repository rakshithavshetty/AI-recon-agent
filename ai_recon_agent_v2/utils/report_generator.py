"""
Report Generator - Fixed v2
Handles N/A, empty lists, and None values gracefully.
Shows method/notes from WHOIS. Improved visual quality.
"""

import json
import os
from datetime import datetime

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def generate_report(session_id: str, results: dict) -> str:
    target = results.get("target", "unknown")
    ai = results.get("ai_analysis", {})
    structured = results.get("structured", {})

    html = _build_html_report(target, ai, structured, session_id)
    filepath = os.path.join(REPORTS_DIR, f"report_{session_id}.html")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    json_path = os.path.join(REPORTS_DIR, f"report_{session_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    return filepath


def _val(v, fallback="N/A"):
    """Safely display a value."""
    if v is None or v == "" or v == []:
        return fallback
    if isinstance(v, list):
        clean = [str(i) for i in v if i and str(i).strip() not in ("", "N/A")]
        return ", ".join(clean) if clean else fallback
    s = str(v).strip()
    return s if s and s != "None" else fallback


def _build_html_report(target: str, ai: dict, structured: dict, session_id: str) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_level = ai.get("risk_level", "info")
    risk_score = ai.get("risk_score", 0)
    risk_colors = {
        "critical": "#dc2626", "high": "#ea580c",
        "medium": "#ca8a04", "low": "#16a34a", "info": "#2563eb"
    }
    rc = risk_colors.get(risk_level, "#6b7280")

    vulns = ai.get("vulnerabilities", [])
    recs = ai.get("recommendations", [])
    posture = ai.get("security_posture", {})
    surface = ai.get("attack_surface_summary", {})
    positives = ai.get("positive_findings", [])
    breakdown = ai.get("risk_breakdown", {})

    whois = structured.get("whois", {})
    dns = structured.get("dns", {})
    subs = structured.get("subdomains", {})
    ports = structured.get("ports", {})
    tech = structured.get("tech", {})

    # -- Build sections --

    # WHOIS note banner
    whois_note = whois.get("note", "")
    whois_method = whois.get("method", "")
    whois_note_html = ""
    if whois_note or whois_method == "dns-fallback":
        whois_note_html = f"""
        <div style="background:#fef9c3;border:1px solid #fde68a;border-radius:8px;padding:12px 16px;margin-bottom:14px;font-size:13px;color:#854d0e">
          ⚠️ <strong>Limited WHOIS data:</strong> WHOIS port 43 was unreachable from this environment.
          Nameserver-based hints shown. <strong>Run the tool on your local machine</strong> for complete registration data (registrar, dates, owner).
        </div>"""

    # Port rows
    port_rows = ""
    open_ports = ports.get("open_ports", [])
    if open_ports:
        risk_colors_port = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#6b7280"}
        for p in open_ports:
            rc2 = risk_colors_port.get(p.get("risk", "low"), "#6b7280")
            banner = (p.get("banner") or "")[:80]
            port_rows += f"""
            <tr>
              <td style="padding:8px 10px;border:1px solid #e5e7eb;font-family:monospace;font-weight:600">{p['port']}</td>
              <td style="padding:8px 10px;border:1px solid #e5e7eb">{p['service']}</td>
              <td style="padding:8px 10px;border:1px solid #e5e7eb"><span style="background:{rc2};color:white;padding:2px 8px;border-radius:4px;font-size:11px;text-transform:uppercase">{p.get('risk','low')}</span></td>
              <td style="padding:8px 10px;border:1px solid #e5e7eb;font-size:12px;font-family:monospace;color:#64748b">{banner}</td>
            </tr>"""

    # Vuln rows
    vuln_rows = ""
    sev_bg = {"critical": "#fef2f2", "high": "#fff7ed", "medium": "#fefce8", "low": "#f0fdf4"}
    sev_color = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}
    for v in vulns:
        bg = sev_bg.get(v["severity"], "#f9fafb")
        color = sev_color.get(v["severity"], "#6b7280")
        vuln_rows += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 10px;border:1px solid #e5e7eb;font-weight:bold;font-size:12px">{v['id']}</td>
          <td style="padding:8px 10px;border:1px solid #e5e7eb;font-weight:500">{v['name']}</td>
          <td style="padding:8px 10px;border:1px solid #e5e7eb"><span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:11px;text-transform:uppercase">{v['severity']}</span></td>
          <td style="padding:8px 10px;border:1px solid #e5e7eb;font-size:13px">{v['description']}</td>
        </tr>"""

    # Recs
    rec_items = "".join(
        f'<li style="margin:8px 0"><strong>#{r["priority"]} [{r["for"]}]:</strong> {r["action"]}</li>'
        for r in recs
    )

    # Positives
    positive_items = "".join(
        f'<li style="margin:5px 0;color:#16a34a">✅ {p}</li>'
        for p in positives
    ) or '<li style="color:#64748b">No positive findings detected</li>'

    # Subdomains
    sub_list_html = ""
    for s in subs.get("discovered_subdomains", [])[:60]:
        sub_list_html += f'<span style="display:inline-block;margin:2px 3px;padding:3px 9px;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:5px;font-size:12px;font-family:monospace;color:#1e40af">{s}</span>'

    # Tech badges
    tech_badges = "".join(
        f'<span style="display:inline-block;margin:3px;padding:5px 12px;background:#1e3a5f;color:white;border-radius:14px;font-size:13px">{t}</span>'
        for t in tech.get("detected_technologies", [])
    )

    # Security headers present/missing
    present_headers = tech.get("security_headers", {}).get("present", [])
    missing_headers = tech.get("security_headers", {}).get("missing", [])
    sec_header_html = ""
    for h in present_headers:
        sec_header_html += f'<span style="display:inline-block;margin:2px 3px;padding:3px 9px;background:#dcfce7;color:#166534;border-radius:4px;font-size:12px">✅ {h}</span>'
    for h in missing_headers:
        sec_header_html += f'<span style="display:inline-block;margin:2px 3px;padding:3px 9px;background:#fee2e2;color:#991b1b;border-radius:4px;font-size:12px">❌ {h}</span>'

    # MX records display
    mx_records = dns.get("mx_records", [])
    mx_display = ", ".join(
        (f"{m['exchange']} (priority {m['priority']})" if isinstance(m, dict) else str(m))
        for m in mx_records
    ) if mx_records else "None"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Recon Report — {target}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; margin: 0; color: #1e293b; }}
    .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 36px 40px; }}
    .header h1 {{ margin: 0 0 8px; font-size: 26px; }}
    .header p {{ margin: 0; opacity: 0.65; font-size: 13px; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 28px 20px; }}
    .card {{ background: white; border-radius: 12px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); padding: 24px; margin-bottom: 22px; }}
    .card h2 {{ margin: 0 0 18px; font-size: 17px; color: #0f172a; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; display:flex; align-items:center; gap:8px; }}
    .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    .stat-box {{ background: #f8fafc; border-radius: 10px; padding: 16px; text-align: center; border: 1px solid #e2e8f0; }}
    .stat-box .num {{ font-size: 34px; font-weight: 800; }}
    .stat-box .lbl {{ font-size: 11px; color: #64748b; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th {{ background: #f8fafc; padding: 10px; text-align: left; border: 1px solid #e5e7eb; font-weight: 600; color: #475569; }}
    .kv {{ display: flex; justify-content: space-between; align-items: flex-start; padding: 9px 0; border-bottom: 1px solid #f1f5f9; font-size: 14px; gap: 16px; }}
    .kv:last-child {{ border-bottom: none; }}
    .kv .k {{ color: #64748b; white-space: nowrap; flex-shrink: 0; }}
    .kv .v {{ font-weight: 500; text-align: right; word-break: break-all; }}
    .score-row {{ display: flex; align-items: center; gap: 24px; flex-wrap: wrap; margin-bottom: 20px; }}
    .score-circle {{ width: 84px; height: 84px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 30px; font-weight: 800; color: white; flex-shrink: 0; }}
    .risk-badge {{ display: inline-block; padding: 7px 18px; border-radius: 20px; font-weight: 700; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; color: white; }}
    @media print {{ body {{ background: white; }} .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
    @media (max-width: 600px) {{ .grid-4 {{ grid-template-columns: repeat(2, 1fr); }} .grid-2 {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
<div class="header">
  <h1>🛡️ AI Reconnaissance Security Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; Session: {session_id}</p>
</div>

<div class="container">

  <div class="card">
    <h2>📊 Risk Summary</h2>
    <div class="score-row">
      <div class="score-circle" style="background:{rc}">{risk_score}</div>
      <div>
        <div style="font-size:12px;color:#64748b;margin-bottom:6px">Overall Risk Level</div>
        <span class="risk-badge" style="background:{rc}">{risk_level.upper()}</span>
      </div>
      <div class="grid-4" style="flex:1;min-width:280px">
        <div class="stat-box"><div class="num" style="color:#dc2626">{breakdown.get('critical',0)}</div><div class="lbl">Critical</div></div>
        <div class="stat-box"><div class="num" style="color:#ea580c">{breakdown.get('high',0)}</div><div class="lbl">High</div></div>
        <div class="stat-box"><div class="num" style="color:#ca8a04">{breakdown.get('medium',0)}</div><div class="lbl">Medium</div></div>
        <div class="stat-box"><div class="num" style="color:#16a34a">{breakdown.get('low',0)}</div><div class="lbl">Low</div></div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>🌐 Attack Surface</h2>
    <div class="grid-4">
      <div class="stat-box"><div class="num">{surface.get('open_ports',0)}</div><div class="lbl">Open Ports</div></div>
      <div class="stat-box"><div class="num" style="color:#dc2626">{surface.get('high_risk_ports',0)}</div><div class="lbl">High-Risk Ports</div></div>
      <div class="stat-box"><div class="num">{surface.get('subdomains_found',0)}</div><div class="lbl">Subdomains</div></div>
      <div class="stat-box"><div class="num">{surface.get('mail_servers',0)}</div><div class="lbl">Mail Servers</div></div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>🔍 WHOIS</h2>
      {whois_note_html}
      <div class="kv"><span class="k">Domain</span><span class="v">{_val(whois.get('domain_name'))}</span></div>
      <div class="kv"><span class="k">Registrar</span><span class="v">{_val(whois.get('registrar'))}</span></div>
      <div class="kv"><span class="k">Organization</span><span class="v">{_val(whois.get('registrant_org'))}</span></div>
      <div class="kv"><span class="k">Country</span><span class="v">{_val(whois.get('registrant_country'))}</span></div>
      <div class="kv"><span class="k">Created</span><span class="v">{_val(whois.get('creation_date'))}</span></div>
      <div class="kv"><span class="k">Expires</span><span class="v">{_val(whois.get('expiration_date'))}</span></div>
      <div class="kv"><span class="k">Nameservers</span><span class="v">{_val(whois.get('nameservers'))}</span></div>
    </div>

    <div class="card">
      <h2>📡 DNS Records</h2>
      <div class="kv"><span class="k">A (IPv4)</span><span class="v">{_val(dns.get('a_records'))}</span></div>
      <div class="kv"><span class="k">AAAA (IPv6)</span><span class="v">{_val(dns.get('aaaa_records'))}</span></div>
      <div class="kv"><span class="k">Nameservers</span><span class="v">{_val(dns.get('ns_records'))}</span></div>
      <div class="kv"><span class="k">Mail (MX)</span><span class="v">{mx_display}</span></div>
      <div class="kv"><span class="k">CNAME</span><span class="v">{_val(dns.get('cname_records'))}</span></div>
      <div class="kv"><span class="k">SPF</span><span class="v">{'✅ Present' if dns.get('has_spf') else '❌ Missing'}</span></div>
      <div class="kv"><span class="k">DMARC</span><span class="v">{'✅ Present' if dns.get('has_dmarc') else '❌ Missing'}</span></div>
    </div>
  </div>

  <div class="card">
    <h2>🔓 Open Ports & Services ({len(open_ports)} found, {ports.get('total_scanned',0)} scanned)</h2>
    {'<p style="color:#64748b">No open ports detected in the scanned range.</p>' if not open_ports else f'<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner / Version</th></tr></thead><tbody>{port_rows}</tbody></table>'}
  </div>

  <div class="card">
    <h2>⚙️ Detected Technologies</h2>
    <div style="margin-bottom:14px">{tech_badges or '<span style="color:#64748b">No technologies fingerprinted (HTTP access blocked in sandbox; run locally)</span>'}</div>
    <div class="kv"><span class="k">Web Server</span><span class="v">{_val(tech.get('server'))}</span></div>
    <div class="kv"><span class="k">CMS</span><span class="v">{_val(tech.get('cms'), 'None detected')}</span></div>
    <div class="kv"><span class="k">Frameworks</span><span class="v">{_val(tech.get('frameworks'), 'None')}</span></div>
    <div class="kv"><span class="k">CDN</span><span class="v">{_val(tech.get('cdn'), 'None detected')}</span></div>
    <div class="kv"><span class="k">HTTPS</span><span class="v">{'✅ Enabled' if tech.get('https_enabled') else '❌ Not enabled'}</span></div>
    {'<div class="kv"><span class="k">Security Headers</span><span class="v"><div style="text-align:right">' + sec_header_html + '</div></span></div>' if sec_header_html else ''}
  </div>

  <div class="card">
    <h2>🌍 Subdomains ({subs.get('total_found', 0)} discovered)</h2>
    <div style="margin-bottom:12px;font-size:13px;color:#64748b">
      {subs.get('ct_log_count',0)} from Certificate Transparency logs &nbsp;|&nbsp;
      {subs.get('bruteforce_count',0)} from DNS brute-force
    </div>
    <div>{sub_list_html or '<span style="color:#64748b">No subdomains found.</span>'}</div>
  </div>

  <div class="card">
    <h2>⚠️ Identified Vulnerabilities ({len(vulns)})</h2>
    {'<p style="color:#16a34a;font-weight:500">✅ No vulnerabilities detected!</p>' if not vulns else f'<table><thead><tr><th>ID</th><th>Vulnerability</th><th>Severity</th><th>Description</th></tr></thead><tbody>{vuln_rows}</tbody></table>'}
  </div>

  <div class="card">
    <h2>💡 Recommendations</h2>
    {'<ol style="margin:0;padding-left:22px;line-height:2">' + rec_items + '</ol>' if recs else '<p style="color:#16a34a">No critical recommendations.</p>'}
  </div>

  <div class="card">
    <h2>✅ Positive Security Findings</h2>
    <ul style="margin:0;padding-left:22px;line-height:1.8">{positive_items}</ul>
  </div>

  <p style="text-align:center;color:#94a3b8;font-size:12px;margin-top:24px">
    Generated by AI Reconnaissance Agent &nbsp;|&nbsp; For authorized use only &nbsp;|&nbsp; {now}
  </p>
</div>
</body>
</html>"""
    return html
