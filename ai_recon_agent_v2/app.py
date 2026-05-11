"""
AI Reconnaissance Agent - Main Application
Flask web application that orchestrates all reconnaissance modules.
"""

from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import threading
from datetime import datetime

from modules.whois_lookup import run_whois
from modules.dns_enum import run_dns_enum
from modules.subdomain_discovery import run_subdomain_discovery
from modules.port_scanner import run_port_scan
from modules.tech_detection import run_tech_detection
from modules.ai_analyzer import analyze_results
from utils.report_generator import generate_report
from utils.data_preprocessor import preprocess_data

app = Flask(__name__)

# In-memory store for scan results
scan_sessions = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    modules_selected = data.get("modules", [
        "whois", "dns", "subdomains", "ports", "tech"
    ])

    if not target:
        return jsonify({"error": "Target domain or IP is required"}), 400

    session_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + target.replace(".", "_")
    scan_sessions[session_id] = {
        "target": target,
        "status": "running",
        "started_at": datetime.now().isoformat(),
        "results": {},
        "progress": 0
    }

    # Run scan in background thread
    thread = threading.Thread(
        target=run_scan_pipeline,
        args=(session_id, target, modules_selected)
    )
    thread.daemon = True
    thread.start()

    return jsonify({"session_id": session_id, "message": "Scan started"})


def run_scan_pipeline(session_id: str, target: str, modules_selected: list):
    """Execute the full reconnaissance pipeline."""
    session = scan_sessions[session_id]
    raw_data = {}
    total_steps = len(modules_selected) + 2  # +2 for preprocessing + AI analysis
    step = 0

    try:
        # Step 1: Run selected modules
        if "whois" in modules_selected:
            session["status_message"] = "Running WHOIS lookup..."
            raw_data["whois"] = run_whois(target)
            step += 1
            session["progress"] = int((step / total_steps) * 100)

        if "dns" in modules_selected:
            session["status_message"] = "Enumerating DNS records..."
            raw_data["dns"] = run_dns_enum(target)
            step += 1
            session["progress"] = int((step / total_steps) * 100)

        if "subdomains" in modules_selected:
            session["status_message"] = "Discovering subdomains..."
            raw_data["subdomains"] = run_subdomain_discovery(target)
            step += 1
            session["progress"] = int((step / total_steps) * 100)

        if "ports" in modules_selected:
            session["status_message"] = "Scanning ports..."
            raw_data["ports"] = run_port_scan(target)
            step += 1
            session["progress"] = int((step / total_steps) * 100)

        if "tech" in modules_selected:
            session["status_message"] = "Detecting technologies..."
            raw_data["tech"] = run_tech_detection(target)
            step += 1
            session["progress"] = int((step / total_steps) * 100)

        # Step 2: Preprocess collected data
        session["status_message"] = "Preprocessing and cleaning data..."
        structured_data = preprocess_data(raw_data)
        step += 1
        session["progress"] = int((step / total_steps) * 100)

        # Step 3: AI-based analysis
        session["status_message"] = "Running AI security analysis..."
        ai_analysis = analyze_results(structured_data, target)
        step += 1
        session["progress"] = 100

        # Compile final results
        session["results"] = {
            "target": target,
            "raw": raw_data,
            "structured": structured_data,
            "ai_analysis": ai_analysis,
            "completed_at": datetime.now().isoformat()
        }

        # Generate report
        report_path = generate_report(session_id, session["results"])
        session["report_path"] = report_path
        session["status"] = "completed"
        session["status_message"] = "Scan complete!"

    except Exception as e:
        session["status"] = "error"
        session["error"] = str(e)
        session["status_message"] = f"Error: {str(e)}"


@app.route("/api/status/<session_id>")
def get_status(session_id):
    session = scan_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "status": session.get("status"),
        "progress": session.get("progress", 0),
        "status_message": session.get("status_message", ""),
        "error": session.get("error")
    })


@app.route("/api/results/<session_id>")
def get_results(session_id):
    session = scan_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404
    if session.get("status") != "completed":
        return jsonify({"error": "Scan not yet completed"}), 202
    return jsonify(session["results"])


@app.route("/api/report/<session_id>")
def download_report(session_id):
    session = scan_sessions.get(session_id)
    if not session or not session.get("report_path"):
        return jsonify({"error": "Report not available"}), 404
    return send_file(session["report_path"], as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=5000)
    
