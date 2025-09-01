#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
import requests
import os
from datetime import datetime, timedelta
import json

# Backend API URL
BACKEND_URL = os.getenv("BACKEND_URL", "http://172.30.0.123:5000")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")

def get_backend_data(endpoint, default=None):
    """Helper function to safely fetch data from backend."""
    try:
        resp = requests.get(f"{BACKEND_URL}/{endpoint}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"Backend error {resp.status_code} for /{endpoint}")
            return default or {}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching /{endpoint}: {e}")
        return default or {}

def post_backend_data(endpoint, params=None, data=None):
    """Helper function to safely post data to backend."""
    try:
        if params:
            resp = requests.post(f"{BACKEND_URL}/{endpoint}", params=params, timeout=30)
        elif data:
            resp = requests.post(f"{BACKEND_URL}/{endpoint}", json=data, timeout=30)
        else:
            resp = requests.post(f"{BACKEND_URL}/{endpoint}", timeout=30)
        return resp.json() if resp.status_code == 200 else {"error": f"Backend error: {resp.status_code}"}
    except requests.exceptions.RequestException as e:
        print(f"Error posting to /{endpoint}: {e}")
        return {"error": f"Connection error: {str(e)}"}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        image = request.form.get("image")
        enrich_cve = request.form.get("enrich_cve") == "on"
        
        if image:
            # Start the scan
            scan_result = post_backend_data("scan", params={"image": image, "enrich_cve": str(enrich_cve).lower()})
            
            if "error" in scan_result:
                flash(f"Scan failed: {scan_result['error']}", "error")
            else:
                flash(f"Scan completed for {image}! Report ID: {scan_result.get('report_id', 'N/A')}", "success")
            
            return redirect(url_for("index"))

    # Fetch dashboard data
    stats = get_backend_data("stats", {"total_scans": 0, "recent_scans_7d": 0, "vulnerability_totals": {}})
    reports = get_backend_data("reports", [])
    
    # Process reports for dashboard
    recent_reports = reports[:5] if reports else []
    
    return render_template("dashboard.html", 
                         stats=stats, 
                         reports=recent_reports,
                         all_reports_count=len(reports))

@app.route("/scan", methods=["POST"])
def scan():
    """Handle AJAX scan requests"""
    data = request.get_json()
    image = data.get("image") if data else request.form.get("image")
    enrich_cve = data.get("enrich_cve", True) if data else request.form.get("enrich_cve") == "on"
    
    if not image:
        return jsonify({"error": "Image name is required"}), 400
    
    scan_result = post_backend_data("scan", params={"image": image, "enrich_cve": str(enrich_cve).lower()})
    return jsonify(scan_result)

@app.route("/reports")
def reports_list():
    """Display all reports with filtering and pagination"""
    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    
    reports = get_backend_data("reports", [])
    
    # Simple pagination (you might want to implement this in backend for large datasets)
    total_reports = len(reports)
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_reports = reports[start_idx:end_idx]
    
    return render_template("reports.html", 
                         reports=paginated_reports,
                         page=page,
                         limit=limit,
                         total=total_reports,
                         has_prev=page > 1,
                         has_next=end_idx < total_reports)

@app.route("/report/<report_id>")
def report(report_id):
    """Display detailed report"""
    report_data = get_backend_data(f"report/{report_id}")
    
    if "error" in report_data:
        flash(f"Error loading report: {report_data['error']}", "error")
        return redirect(url_for("reports_list"))
    
    # Process vulnerability data for better display
    processed_report = process_report_data(report_data)
    
    return render_template("report_detail.html", report=processed_report)

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    """Display CVE details"""
    cve_data = get_backend_data(f"cve/{cve_id}")
    
    if "error" in cve_data:
        flash(f"CVE not found: {cve_id}", "error")
        return redirect(url_for("index"))
    
    return render_template("cve_detail.html", cve=cve_data, cve_id=cve_id)

@app.route("/api/scan/status/<report_id>")
def scan_status(report_id):
    """API endpoint to check scan status"""
    report_data = get_backend_data(f"report/{report_id}")
    
    if "error" in report_data:
        return jsonify({"status": "error", "message": "Report not found"}), 404
    
    return jsonify({
        "status": "completed",
        "summary": report_data.get("summary", {}),
        "elapsed": report_data.get("elapsed", 0),
        "enriched": report_data.get("enriched", False)
    })

@app.route("/api/stats")
def api_stats():
    """API endpoint for dashboard stats"""
    return jsonify(get_backend_data("stats"))

@app.route('/favicon.ico')
def favicon():
    """Serve favicon or return 204 No Content to prevent 404 errors."""
    # Option 1: Return empty response (no favicon)
    from flask import Response
    return Response(status=204)

def process_report_data(report_data):
    """Process report data for better frontend display"""
    processed = report_data.copy()
    
    # Extract and organize vulnerabilities
    all_vulnerabilities = []
    for result in report_data.get("report", {}).get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vuln["Target"] = result.get("Target", "")
            vuln["Type"] = result.get("Type", "")
            all_vulnerabilities.append(vuln)
    
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_vulnerabilities.sort(key=lambda x: severity_order.get(x.get("Severity", "UNKNOWN"), 4))
    
    processed["all_vulnerabilities"] = all_vulnerabilities
    processed["vulnerability_count"] = len(all_vulnerabilities)
    
    # Group by severity for charts
    severity_groups = {}
    for vuln in all_vulnerabilities:
        sev = vuln.get("Severity", "UNKNOWN")
        if sev not in severity_groups:
            severity_groups[sev] = []
        severity_groups[sev].append(vuln)
    
    processed["severity_groups"] = severity_groups
    
    return processed

@app.template_filter('datetime')
def datetime_filter(value):
    """Format datetime for templates"""
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return value
    return value

@app.template_filter('risk_level')
def risk_level_filter(summary):
    """Calculate risk level from summary"""
    if not summary:
        return "UNKNOWN", "secondary"
    
    risk_score = (summary.get("CRITICAL", 0) * 4 + 
                 summary.get("HIGH", 0) * 3 + 
                 summary.get("MEDIUM", 0) * 2 + 
                 summary.get("LOW", 0) * 1)
    
    if risk_score > 100:
        return "CRITICAL", "danger"
    elif risk_score > 50:
        return "HIGH", "warning"
    elif risk_score > 20:
        return "MEDIUM", "info"
    else:
        return "LOW", "success"

@app.template_filter('severity_badge')
def severity_badge_filter(severity):
    """Get Bootstrap badge class for severity"""
    severity_map = {
        "CRITICAL": "danger",
        "HIGH": "warning", 
        "MEDIUM": "info",
        "LOW": "success",
        "UNKNOWN": "secondary"
    }
    return severity_map.get(severity, "secondary")

@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)