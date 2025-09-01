#!/usr/bin/env python3
import os
import subprocess
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import asyncio
import aiohttp

from flask import Flask, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import requests
from database import postgres_db
import subprocess
import tempfile

# ---------------- CONFIG ----------------
load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")
NVD_API_KEY = os.getenv("NVD_API_KEY")  # Optional but recommended for higher rate limits

# Flask app
app = Flask(__name__)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("VulnScannerBackend")

# MongoDB setup
if not MONGO_URI:
    raise RuntimeError("MONGO_URI must be set in .env")
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["vuln_scanner"]
reports_collection = db["reports"]
cve_cache_collection = db["cve_cache"]

# ---------------- CVE DATABASE INTEGRATION ----------------
class CVEDatabase:
    """Handle CVE database operations and caching."""
    
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_duration = timedelta(hours=24)  # Cache CVE data for 24 hours
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details with caching."""
        # Check cache first
        cached = cve_cache_collection.find_one({"cve_id": cve_id})
        if cached and datetime.utcnow() - cached["cached_at"] < self.cache_duration:
            logger.info(f"Using cached CVE data for {cve_id}")
            return cached["data"]
        
        # Fetch from NVD API
        try:
            headers = {}
            if NVD_API_KEY:
                headers["apiKey"] = NVD_API_KEY
            
            params = {"cveId": cve_id}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.nvd_base_url, 
                    params=params, 
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        cve_data = self._extract_cve_info(data)
                        
                        # Cache the result
                        cve_cache_collection.replace_one(
                            {"cve_id": cve_id},
                            {
                                "cve_id": cve_id,
                                "data": cve_data,
                                "cached_at": datetime.utcnow()
                            },
                            upsert=True
                        )
                        
                        logger.info(f"Fetched and cached CVE data for {cve_id}")
                        return cve_data
                    else:
                        logger.warning(f"Failed to fetch CVE {cve_id}: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
            return None
    
    def _extract_cve_info(self, nvd_response: Dict) -> Dict:
        """Extract relevant CVE information from NVD response."""
        if not nvd_response.get("vulnerabilities"):
            return {}
        
        vuln = nvd_response["vulnerabilities"][0]["cve"]
        
        # Extract CVSS scores
        cvss_scores = {}
        metrics = vuln.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_scores["v3.1"] = {
                "score": cvss_v31.get("baseScore"),
                "severity": cvss_v31.get("baseSeverity"),
                "vector": cvss_v31.get("vectorString")
            }
        
        if "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_scores["v2"] = {
                "score": cvss_v2.get("baseScore"),
                "severity": cvss_v2.get("baseSeverity"),
                "vector": cvss_v2.get("vectorString")
            }
        
        # Extract references
        references = []
        for ref in vuln.get("references", []):
            references.append({
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ref.get("tags", [])
            })
        
        return {
            "id": vuln.get("id"),
            "published": vuln.get("published"),
            "lastModified": vuln.get("lastModified"),
            "description": vuln.get("descriptions", [{}])[0].get("value", ""),
            "cvss_scores": cvss_scores,
            "references": references,
            "cwe": [w.get("value") for w in vuln.get("weaknesses", [])],
            "configurations": vuln.get("configurations", {})
        }
    
    async def enrich_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Enrich vulnerability data with CVE database information."""
        enriched = []
        semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
        
        async def enrich_single_vuln(vuln):
            async with semaphore:
                cve_id = vuln.get("VulnerabilityID")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_details = await self.get_cve_details(cve_id)
                    if cve_details:
                        vuln["cve_details"] = cve_details
                return vuln
        
        tasks = [enrich_single_vuln(vuln.copy()) for vuln in vulnerabilities]
        enriched = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        return [v for v in enriched if not isinstance(v, Exception)]

# Initialize CVE database handler
cve_db = CVEDatabase()

# ---------------- ENHANCED SCAN LOGIC ----------------
def run_scan(image_name: str, enrich_cve: bool = True) -> dict:
    """Run Trivy scan on a Docker image and store report in MongoDB."""
    start_time = time.time()
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error("Trivy failed: %s", str(e))
        return {"error": f"Trivy failed: {str(e)}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Trivy output: %s", str(e))
        return {"error": f"Failed to parse Trivy output: {str(e)}"}
    
    elapsed = round(time.time() - start_time, 2)

    # Count vulnerabilities
    summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    all_vulnerabilities = []
    
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            sev = v.get("Severity")
            if sev in summary:
                summary[sev] += 1
            all_vulnerabilities.append(v)

    # Enrich with CVE data if requested
    if enrich_cve and all_vulnerabilities:
        logger.info(f"Enriching {len(all_vulnerabilities)} vulnerabilities with CVE data")
        try:
            # Run async enrichment
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            enriched_vulns = loop.run_until_complete(
                cve_db.enrich_vulnerabilities(all_vulnerabilities)
            )
            loop.close()
            
            # Update the original data structure
            vuln_index = 0
            for r in data.get("Results", []):
                if "Vulnerabilities" in r:
                    for i in range(len(r["Vulnerabilities"])):
                        if vuln_index < len(enriched_vulns):
                            r["Vulnerabilities"][i] = enriched_vulns[vuln_index]
                            vuln_index += 1
            
            logger.info("CVE enrichment completed")
        except Exception as e:
            logger.error(f"CVE enrichment failed: {str(e)}")

    # Prepare document
    report_doc = {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report": data,
        "enriched": enrich_cve,
        "created_at": datetime.utcnow()
    }
    report_id = reports_collection.insert_one(report_doc).inserted_id

    # Send enhanced Slack notification
    send_slack_notification(image_name, elapsed, summary, str(report_id), enrich_cve)

    return {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report_id": str(report_id),
        "enriched": enrich_cve
    }

# ---------------- ENHANCED SLACK NOTIFICATIONS ----------------
def send_slack_notification(image_name: str, elapsed: float, summary: dict, report_id: str, enriched: bool = False):
    """Send an enhanced Slack notification with CVE insights."""
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack webhook not set, skipping notification")
        return

    # Calculate risk score
    risk_score = (summary["CRITICAL"] * 4 + summary["HIGH"] * 3 + 
                 summary["MEDIUM"] * 2 + summary["LOW"] * 1)
    
    risk_level = "🟢 LOW"
    if risk_score > 100:
        risk_level = "🔴 CRITICAL"
    elif risk_score > 50:
        risk_level = "🟠 HIGH"
    elif risk_score > 20:
        risk_level = "🟡 MEDIUM"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ Vulnerability Scan Completed"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Image:*\n{image_name}"},
                {"type": "mrkdwn", "text": f"*Duration:*\n{elapsed} sec"},
                {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_level}"},
                {"type": "mrkdwn", "text": f"*Report ID:*\n{report_id}"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Vulnerability Summary* {'(CVE Enhanced)' if enriched else ''}"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"🔴 *CRITICAL:* {summary['CRITICAL']}"},
                {"type": "mrkdwn", "text": f"🟠 *HIGH:* {summary['HIGH']}"},
                {"type": "mrkdwn", "text": f"🟡 *MEDIUM:* {summary['MEDIUM']}"},
                {"type": "mrkdwn", "text": f"🟢 *LOW:* {summary['LOW']}"}
            ]
        }
    ]

    if enriched:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "✨ This scan includes real-time CVE database enrichment with CVSS scores and references"
                }
            ]
        })

    payload = {"blocks": blocks}

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code != 200:
            logger.error("Slack notification failed: %s", response.text)
        else:
            logger.info("Slack notification sent successfully")
    except Exception as e:
        logger.error("Slack notification error: %s", str(e))

# ---------------- NEW CVE-SPECIFIC ROUTES ----------------
@app.route("/cve/<cve_id>", methods=["GET"])
def get_cve_details(cve_id):
    """Get detailed information about a specific CVE."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cve_details = loop.run_until_complete(cve_db.get_cve_details(cve_id))
        loop.close()
        
        if cve_details:
            return jsonify(cve_details)
        else:
            return jsonify({"error": "CVE not found or API error"}), 404
    except Exception as e:
        logger.error(f"Error in get_cve_details: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/cve/search", methods=["GET"])
def search_cves():
    """Search for CVEs by keyword or date range."""
    keyword = request.args.get("keyword")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    
    if not any([keyword, start_date, end_date]):
        return jsonify({"error": "Please provide keyword, start_date, or end_date"}), 400
    
    # This would require additional NVD API integration for full search functionality
    return jsonify({"message": "CVE search functionality - coming soon"}), 501

@app.route("/cve/cache/clear", methods=["POST"])
def clear_cve_cache():
    """Clear the CVE cache."""
    try:
        result = cve_cache_collection.delete_many({})
        return jsonify({"message": f"Cleared {result.deleted_count} cached CVE entries"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- ENHANCED ROUTES ----------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Enhanced Vulnerability Scanner Backend",
        "version": "2.0",
        "features": ["Trivy Integration", "CVE Database", "MongoDB Storage", "Slack Notifications"],
        "routes": {
            "GET /reports": "List all report IDs",
            "GET /report/<id>": "Fetch specific report JSON",
            "POST /scan?image=<docker_image>&enrich_cve=true": "Run enhanced scan with CVE data",
            "GET /scan?image=<docker_image>&enrich_cve=false": "Run basic scan (browser testing)",
            "GET /cve/<cve_id>": "Get detailed CVE information",
            "GET /cve/search?keyword=<term>": "Search CVEs (coming soon)",
            "POST /cve/cache/clear": "Clear CVE cache",
            "GET /stats": "Get scanning statistics",
            "GET /health": "Health check endpoint"
        }
    })

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    try:
        # Check MongoDB connection
        mongo_client.admin.command('ping')
        mongo_status = "healthy"
    except Exception as e:
        mongo_status = f"unhealthy: {str(e)}"
    
    # Check Trivy availability
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        trivy_status = "healthy"
    except Exception as e:
        trivy_status = f"unhealthy: {str(e)}"
    
    status = {
        "status": "healthy" if mongo_status == "healthy" and trivy_status == "healthy" else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "mongodb": mongo_status,
            "trivy": trivy_status,
            "slack_webhook": "configured" if SLACK_WEBHOOK_URL else "not configured",
            "nvd_api_key": "configured" if NVD_API_KEY else "not configured"
        }
    }
    
    return jsonify(status), 200 if status["status"] == "healthy" else 503

@app.route("/scan", methods=["GET", "POST"])
def scan():
    image = request.args.get("image")
    enrich_cve = request.args.get("enrich_cve", "true").lower() == "true"
    
    if not image:
        return jsonify({"error": "Please provide ?image=<docker_image>"}), 400
    
    try:
        result = run_scan(image, enrich_cve)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/stats", methods=["GET"])
def get_stats():
    """Get scanning statistics."""
    try:
        total_scans = reports_collection.count_documents({})
        recent_scans = reports_collection.count_documents({
            "created_at": {"$gte": datetime.utcnow() - timedelta(days=7)}
        })
        
        # Aggregate vulnerability counts
        pipeline = [
            {"$group": {
                "_id": None,
                "total_critical": {"$sum": "$summary.CRITICAL"},
                "total_high": {"$sum": "$summary.HIGH"},
                "total_medium": {"$sum": "$summary.MEDIUM"},
                "total_low": {"$sum": "$summary.LOW"}
            }}
        ]
        
        agg_result = list(reports_collection.aggregate(pipeline))
        vuln_totals = agg_result[0] if agg_result else {
            "total_critical": 0, "total_high": 0, "total_medium": 0, "total_low": 0
        }
        
        # Remove the _id field from aggregation result
        if "_id" in vuln_totals:
            del vuln_totals["_id"]
        
        return jsonify({
            "total_scans": total_scans,
            "recent_scans_7d": recent_scans,
            "vulnerability_totals": vuln_totals,
            "cve_cache_size": cve_cache_collection.count_documents({})
        })
    except Exception as e:
        logger.error(f"Error in get_stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports", methods=["GET"])
def list_reports():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        reports = reports_collection.find(
            {}, 
            {"_id": 1, "image": 1, "created_at": 1, "summary": 1, "enriched": 1}
        ).sort("created_at", -1).limit(limit)
        
        result = []
        for r in reports:
            result.append({
                "id": str(r["_id"]), 
                "image": r["image"], 
                "created_at": r["created_at"], 
                "summary": r.get("summary", {}), 
                "enriched": r.get("enriched", False)
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in list_reports: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/report/<report_id>", methods=["GET"])
def get_report(report_id):
    try:
        report = reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        report["_id"] = str(report["_id"])
        return jsonify(report)
    except Exception as e:
        logger.error(f"Error in get_report: {str(e)}")
        return jsonify({"error": "Invalid report ID"}), 400

@app.route("/report/<report_id>", methods=["DELETE"])
def delete_report(report_id):
    """Delete a specific report."""
    try:
        result = reports_collection.delete_one({"_id": ObjectId(report_id)})
        if result.deleted_count == 0:
            return jsonify({"error": "Report not found"}), 404
        
        return jsonify({"message": "Report deleted successfully"})
    except Exception as e:
        logger.error(f"Error in delete_report: {str(e)}")
        return jsonify({"error": "Invalid report ID"}), 400

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ---------------- MAIN ----------------
if __name__ == "__main__":
    logger.info("Starting Enhanced Vulnerability Scanner Backend v2.0")
    logger.info(f"MongoDB URI configured: {bool(MONGO_URI)}")
    logger.info(f"Slack webhook configured: {bool(SLACK_WEBHOOK_URL)}")
    logger.info(f"NVD API key configured: {bool(NVD_API_KEY)}")
    
    app.run(host="0.0.0.0", port=5000, debug=True)