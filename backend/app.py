#!/usr/bin/env python3
"""
Enhanced Container Registry Vulnerability Scanner v2.1
Complete backend implementation with automated monitoring
"""
import os
import subprocess
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId

# Load environment variables
load_dotenv()

# Configuration
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")
NVD_API_KEY = os.getenv("NVD_API_KEY")
DOCKER_REGISTRY_URL = os.getenv("DOCKER_REGISTRY_URL", "https://registry-1.docker.io")
DOCKER_USERNAME = os.getenv("DOCKER_USERNAME")
DOCKER_PASSWORD = os.getenv("DOCKER_PASSWORD")

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
registry_cache_collection = db["registry_cache"]

class DockerRegistryClient:
    """Docker Hub API client for repository management."""
    
    def __init__(self):
        self.registry_url = DOCKER_REGISTRY_URL
        self.username = DOCKER_USERNAME
        self.password = DOCKER_PASSWORD
        self.auth_token = None
    
    def get_user_repositories(self, username: str = "xxradeonfx") -> List[str]:
        """Get all repositories for a specific user."""
        try:
            url = f"https://hub.docker.com/v2/repositories/{username}/"
            params = {"page_size": 100}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                repositories = [repo["name"] for repo in data.get("results", [])]
                logger.info(f"Found {len(repositories)} repositories for user {username}")
                return repositories
            else:
                logger.error(f"Failed to fetch repositories: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error fetching repositories: {str(e)}")
            return []
    
    def get_repository_tags(self, repository: str, limit: int = 10) -> List[str]:
        """Get tags for a repository."""
        try:
            url = f"https://hub.docker.com/v2/repositories/{repository}/tags"
            params = {"page_size": limit}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                tags = [tag["name"] for tag in data.get("results", [])]
                return tags
            else:
                logger.warning(f"Failed to fetch tags for {repository}")
                return []
        except Exception as e:
            logger.error(f"Error fetching tags for {repository}: {str(e)}")
            return []

class CVEDatabase:
    """CVE database integration for vulnerability enrichment."""
    
    def __init__(self):
        self.api_key = NVD_API_KEY
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
    
    def get_cve_details(self, cve_id: str) -> Dict:
        """Get detailed CVE information from NVD."""
        # Check cache first
        cached = cve_cache_collection.find_one({"_id": cve_id})
        if cached and cached.get("expires_at", datetime.min) > datetime.utcnow():
            return cached["data"]
        
        try:
            params = {"cveId": cve_id}
            response = self.session.get(self.base_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("vulnerabilities"):
                    vuln_data = data["vulnerabilities"][0]["cve"]
                    
                    # Process CVE data
                    cve_details = {
                        "id": cve_id,
                        "description": vuln_data.get("descriptions", [{}])[0].get("value", ""),
                        "published": vuln_data.get("published"),
                        "lastModified": vuln_data.get("lastModified"),
                        "cvss_scores": {},
                        "references": []
                    }
                    
                    # Extract CVSS scores
                    metrics = vuln_data.get("metrics", {})
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version in metrics and metrics[version]:
                            metric = metrics[version][0]
                            cvss = metric.get("cvssData", {})
                            cve_details["cvss_scores"][version.replace("cvssMetricV", "v")] = {
                                "score": cvss.get("baseScore"),
                                "severity": cvss.get("baseSeverity", "UNKNOWN"),
                                "vector": cvss.get("vectorString")
                            }
                    
                    # Extract references
                    refs = vuln_data.get("references", [])
                    for ref in refs[:10]:  # Limit references
                        cve_details["references"].append({
                            "url": ref.get("url"),
                            "source": ref.get("source"),
                            "tags": ref.get("tags", [])
                        })
                    
                    # Cache for 24 hours
                    cve_cache_collection.replace_one(
                        {"_id": cve_id},
                        {
                            "_id": cve_id,
                            "data": cve_details,
                            "expires_at": datetime.utcnow() + timedelta(hours=24),
                            "updated_at": datetime.utcnow()
                        },
                        upsert=True
                    )
                    
                    return cve_details
                else:
                    logger.warning(f"No data found for CVE {cve_id}")
                    return {}
            else:
                logger.error(f"CVE API error: {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {str(e)}")
            return {}

# Initialize components
registry_client = DockerRegistryClient()
cve_database = CVEDatabase()

# Flask app
app = Flask(__name__)

def run_scan(image_name: str, enrich_cve: bool = False) -> Dict:
    """Run vulnerability scan using Trivy."""
    try:
        start_time = time.time()
        logger.info(f"Starting scan for image: {image_name}")
        
        # Run Trivy scan
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--quiet",
            image_name
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            error_msg = f"Trivy scan failed: {result.stderr}"
            logger.error(error_msg)
            return {"error": error_msg}
        
        # Parse results
        try:
            scan_data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse scan results: {str(e)}"}
        
        # Process vulnerabilities
        all_vulnerabilities = []
        vulnerability_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        
        for scan_result in scan_data.get("Results", []):
            for vuln in scan_result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN")
                vulnerability_summary[severity] = vulnerability_summary.get(severity, 0) + 1
                
                # Enrich with CVE data if requested
                if enrich_cve and vuln.get("VulnerabilityID", "").startswith("CVE-"):
                    cve_details = cve_database.get_cve_details(vuln["VulnerabilityID"])
                    if cve_details:
                        vuln["cve_details"] = cve_details
                
                all_vulnerabilities.append(vuln)
        
        elapsed = round(time.time() - start_time, 2)
        
        # Prepare report
        report = {
            "image": image_name,
            "scan_type": "single",
            "report": scan_data,
            "summary": vulnerability_summary,
            "total_vulnerabilities": len(all_vulnerabilities),
            "elapsed": elapsed,
            "enriched": enrich_cve,
            "created_at": datetime.utcnow(),
            "version": "2.1"
        }
        
        # Save to database
        report_id = reports_collection.insert_one(report).inserted_id
        
        # Send Slack notification
        if SLACK_WEBHOOK_URL:
            send_slack_notification(report, str(report_id))
        
        logger.info(f"Scan completed for {image_name} in {elapsed}s")
        
        return {
            "message": f"Scan completed for {image_name}",
            "report_id": str(report_id),
            "summary": vulnerability_summary,
            "elapsed": elapsed,
            "enriched": enrich_cve
        }
        
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out after 5 minutes"}
    except Exception as e:
        error_msg = f"Scan failed: {str(e)}"
        logger.error(error_msg)
        return {"error": error_msg}

def send_slack_notification(report: Dict, report_id: str):
    """Send scan results to Slack."""
    if not SLACK_WEBHOOK_URL:
        return
    
    try:
        summary = report.get("summary", {})
        image = report.get("image", "Unknown")
        
        # Calculate risk level
        risk_score = (summary.get("CRITICAL", 0) * 4 + summary.get("HIGH", 0) * 3 + 
                     summary.get("MEDIUM", 0) * 2 + summary.get("LOW", 0) * 1)
        
        if risk_score > 50:
            color = "#dc3545"  # Red
            risk_level = "🔴 HIGH RISK"
        elif risk_score > 20:
            color = "#fd7e14"  # Orange
            risk_level = "🟠 MEDIUM RISK"
        elif risk_score > 0:
            color = "#ffc107"  # Yellow
            risk_level = "🟡 LOW RISK"
        else:
            color = "#28a745"  # Green
            risk_level = "🟢 SECURE"
        
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🔍 Vulnerability Scan Complete"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Image:*\n{image}"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_level}"},
                    {"type": "mrkdwn", "text": f"*Scan Duration:*\n{report.get('elapsed', 0)} seconds"},
                    {"type": "mrkdwn", "text": f"*Enhanced:*\n{'✅ CVE Enhanced' if report.get('enriched') else '❌ Basic Scan'}"}
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Vulnerability Summary*"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"🔴 *CRITICAL:* {summary.get('CRITICAL', 0)}"},
                    {"type": "mrkdwn", "text": f"🟠 *HIGH:* {summary.get('HIGH', 0)}"},
                    {"type": "mrkdwn", "text": f"🟡 *MEDIUM:* {summary.get('MEDIUM', 0)}"},
                    {"type": "mrkdwn", "text": f"🟢 *LOW:* {summary.get('LOW', 0)}"}
                ]
            }
        ]
        
        payload = {
            "blocks": blocks,
            "attachments": [{
                "color": color,
                "fields": [
                    {"title": "Report ID", "value": f"`{report_id}`", "short": True},
                    {"title": "Total Issues", "value": str(sum(summary.values())), "short": True}
                ]
            }]
        }
        
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info(f"Slack notification sent for {image}")
        else:
            logger.error(f"Failed to send Slack notification: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error sending Slack notification: {str(e)}")

# API Routes
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Container Vulnerability Scanner",
        "version": "2.1",
        "timestamp": datetime.utcnow().isoformat()
    })

@app.route("/scan", methods=["POST"])
def scan_endpoint():
    """Scan a single Docker image."""
    image = request.args.get("image") or request.json.get("image") if request.is_json else None
    enrich_cve = str(request.args.get("enrich_cve", "false")).lower() == "true"
    
    if not image:
        return jsonify({"error": "Image parameter is required"}), 400
    
    result = run_scan(image, enrich_cve)
    
    if "error" in result:
        return jsonify(result), 500
    
    return jsonify(result)

@app.route("/reports", methods=["GET"])
def get_reports():
    """Get all scan reports."""
    try:
        limit = int(request.args.get("limit", 50))
        scan_type = request.args.get("type", "all")
        
        query = {}
        if scan_type != "all":
            query["scan_type"] = scan_type
        
        reports = list(reports_collection.find(query).sort("created_at", -1).limit(limit))
        
        for report in reports:
            report["id"] = str(report["_id"])
            del report["_id"]
        
        return jsonify(reports)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/report/<report_id>", methods=["GET"])
def get_report(report_id):
    """Get a specific report."""
    try:
        report = reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        report["id"] = str(report["_id"])
        del report["_id"]
        
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": "Invalid report ID"}), 400

@app.route("/registry/repositories", methods=["GET"])
def get_registry_repositories():
    """Get available repositories from Docker Hub."""
    try:
        repositories = registry_client.get_user_repositories()
        return jsonify({
            "registry_url": registry_client.registry_url,
            "repositories": repositories,
            "count": len(repositories)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/registry/scan", methods=["POST"])
def registry_batch_scan():
    """Perform batch scan on multiple repositories."""
    try:
        data = request.get_json()
        repositories = data.get("repositories", [])
        max_images = int(data.get("max_images", 20))
        
        if not repositories:
            return jsonify({"error": "No repositories specified"}), 400
        
        logger.info(f"Starting registry batch scan for {len(repositories)} repositories")
        
        scanned_images = []
        total_vulnerabilities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        images_per_repo = max(1, max_images // len(repositories))
        
        for repo in repositories:
            tags = registry_client.get_repository_tags(repo, images_per_repo)
            
            for tag in tags[:images_per_repo]:
                image_name = f"{repo}:{tag}"
                logger.info(f"Scanning {image_name}")
                
                scan_result = run_scan(image_name, enrich_cve=True)
                
                if "error" not in scan_result:
                    scanned_images.append({
                        "image": image_name,
                        "repository": repo,
                        "tag": tag,
                        "summary": scan_result.get("summary", {}),
                        "report_id": scan_result.get("report_id")
                    })
                    
                    # Aggregate vulnerabilities
                    for severity, count in scan_result.get("summary", {}).items():
                        total_vulnerabilities[severity] = total_vulnerabilities.get(severity, 0) + count
        
        # Create registry scan report
        registry_report = {
            "scan_type": "registry_batch",
            "repositories": repositories,
            "scanned_images": scanned_images,
            "total_scanned": len(scanned_images),
            "total_vulnerabilities": total_vulnerabilities,
            "created_at": datetime.utcnow(),
            "version": "2.1"
        }
        
        registry_scan_id = reports_collection.insert_one(registry_report).inserted_id
        
        return jsonify({
            "message": "Registry batch scan completed",
            "registry_scan_id": str(registry_scan_id),
            "total_scanned": len(scanned_images),
            "total_queued": len(scanned_images),
            "summary": total_vulnerabilities
        })
        
    except Exception as e:
        logger.error(f"Registry batch scan failed: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/stats", methods=["GET"])
def get_statistics():
    """Get system statistics."""
    try:
        # Count reports
        total_scans = reports_collection.count_documents({})
        
        # Recent scans (7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_scans = reports_collection.count_documents({
            "created_at": {"$gte": week_ago}
        })
        
        # Registry batch scans
        registry_scans = reports_collection.count_documents({
            "scan_type": "registry_batch"
        })
        
        # Single image scans
        single_scans = reports_collection.count_documents({
            "$or": [
                {"scan_type": "single"},
                {"scan_type": {"$exists": False}}
            ]
        })
        
        # Aggregate vulnerability totals
        pipeline = [
            {"$group": {
                "_id": None,
                "total_critical": {"$sum": "$summary.CRITICAL"},
                "total_high": {"$sum": "$summary.HIGH"},
                "total_medium": {"$sum": "$summary.MEDIUM"},
                "total_low": {"$sum": "$summary.LOW"}
            }}
        ]
        
        vuln_totals = list(reports_collection.aggregate(pipeline))
        vulnerability_totals = vuln_totals[0] if vuln_totals else {
            "total_critical": 0,
            "total_high": 0,
            "total_medium": 0,
            "total_low": 0
        }
        
        return jsonify({
            "total_scans": total_scans,
            "recent_scans_7d": recent_scans,
            "registry_batch_scans": registry_scans,
            "single_image_scans": single_scans,
            "vulnerability_totals": vulnerability_totals,
            "cve_cache_size": cve_cache_collection.count_documents({})
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/cve/<cve_id>", methods=["GET"])
def get_cve_details_endpoint(cve_id):
    """Get CVE details."""
    try:
        cve_details = cve_database.get_cve_details(cve_id)
        if not cve_details:
            return jsonify({"error": "CVE not found"}), 404
        
        return jsonify(cve_details)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Initialize monitoring AFTER Flask app is fully configured
def initialize_monitoring():
    """Initialize the monitoring system with proper component injection."""
    try:
        # Import monitoring components
        from automated_registry_monitor import create_monitoring_app, registry_monitor
        
        # Pass required components to the monitoring system
        import automated_registry_monitor as monitor_module
        
        # Inject components into the monitoring module
        monitor_module.registry_client = registry_client
        monitor_module.run_scan = run_scan
        monitor_module.send_slack_notification = send_slack_notification
        monitor_module.reports_collection = reports_collection
        monitor_module.db = db
        monitor_module.logger = logger
        
        # Initialize the monitoring app with our Flask instance
        create_monitoring_app(app)
        
        # Initialize the registry monitor
        registry_monitor.initialize()
        
        logger.info("✅ Monitoring system initialized successfully")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize monitoring system: {e}")
        print(f"Warning: Monitoring system initialization failed: {e}")

if __name__ == "__main__":
    logger.info("Starting Enhanced Container Registry Vulnerability Scanner v2.1")
    logger.info(f"MongoDB URI configured: {bool(MONGO_URI)}")
    logger.info(f"Slack webhook configured: {bool(SLACK_WEBHOOK_URL)}")
    logger.info(f"Registry URL: {registry_client.registry_url}")
    
    # Initialize monitoring system after app is configured
    initialize_monitoring()
    
    logger.info("Starting Enhanced Container Registry Scanner with Auto-Monitoring")
    
    app.run(host="0.0.0.0", port=5000, debug=True)