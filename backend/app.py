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
import requests
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId

# ---------------- CONFIG ----------------
load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")
NVD_API_KEY = os.getenv("NVD_API_KEY")
DOCKER_REGISTRY_URL = os.getenv("DOCKER_REGISTRY_URL", "https://registry-1.docker.io")
DOCKER_USERNAME = os.getenv("DOCKER_USERNAME")
DOCKER_PASSWORD = os.getenv("DOCKER_PASSWORD")

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
registry_cache_collection = db["registry_cache"]

# ---------------- DOCKER REGISTRY INTEGRATION ----------------
class DockerRegistryClient:
    """Handle Docker registry operations and image discovery."""
    
    def __init__(self):
        self.registry_url = DOCKER_REGISTRY_URL
        self.username = DOCKER_USERNAME
        self.password = DOCKER_PASSWORD
        self.session = requests.Session()
        
        if self.username and self.password:
            self.session.auth = (self.username, self.password)
    
    def list_repositories(self, registry_url: str = None) -> List[str]:
        """List all repositories in a Docker registry."""
        try:
            url = registry_url or self.registry_url
            # For Docker Hub API v2
            if "docker.io" in url:
                # Docker Hub requires different API endpoint
                return self._list_dockerhub_repositories()
            else:
                # Standard registry v2 API
                response = self.session.get(f"{url}/v2/_catalog")
                if response.status_code == 200:
                    data = response.json()
                    return data.get("repositories", [])
                else:
                    logger.error(f"Failed to list repositories: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Error listing repositories: {str(e)}")
            return []
    
    def _list_dockerhub_repositories(self) -> List[str]:
        """List repositories from Docker Hub (requires organization or user context)."""
        # This is a simplified version - in practice you'd need to specify
        # organization/user or use search API
        popular_images = [
            "nginx", "alpine", "ubuntu", "centos", "debian", "node", "python", 
            "mysql", "postgres", "redis", "mongo", "httpd", "php", "java",
            "golang", "ruby", "tomcat", "jenkins", "elasticsearch", "kibana"
        ]
        return popular_images
    
    def list_image_tags(self, repository: str, limit: int = 50) -> List[Dict]:
        """List tags for a specific repository."""
        try:
            if "docker.io" in self.registry_url:
                return self._list_dockerhub_tags(repository, limit)
            else:
                url = f"{self.registry_url}/v2/{repository}/tags/list"
                response = self.session.get(url)
                if response.status_code == 200:
                    data = response.json()
                    tags = data.get("tags", [])[:limit]
                    return [{"name": tag, "repository": repository} for tag in tags]
                else:
                    logger.error(f"Failed to list tags for {repository}: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Error listing tags for {repository}: {str(e)}")
            return []
    
    def _list_dockerhub_tags(self, repository: str, limit: int = 50) -> List[Dict]:
        """List tags from Docker Hub API."""
        try:
            # Use Docker Hub API
            url = f"https://hub.docker.com/v2/repositories/{repository}/tags"
            params = {"page_size": limit}
            response = requests.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])
                return [
                    {
                        "name": tag["name"],
                        "repository": repository,
                        "last_updated": tag.get("last_updated"),
                        "full_size": tag.get("full_size"),
                        "architecture": tag.get("images", [{}])[0].get("architecture", "amd64")
                    }
                    for tag in results
                ]
            else:
                logger.warning(f"Docker Hub API failed for {repository}: {response.status_code}")
                # Fallback to common tags
                common_tags = ["latest", "stable", "alpine", "slim"]
                return [{"name": tag, "repository": repository} for tag in common_tags]
        except Exception as e:
            logger.error(f"Error fetching Docker Hub tags for {repository}: {str(e)}")
            return [{"name": "latest", "repository": repository}]
    
    def scan_registry_images(self, repositories: List[str], max_images: int = 100) -> Dict:
        """Scan multiple images from registry repositories."""
        scan_queue = []
        
        for repo in repositories:
            tags = self.list_image_tags(repo, limit=5)  # Limit tags per repo
            for tag_info in tags:
                image_name = f"{repo}:{tag_info['name']}"
                scan_queue.append({
                    "image": image_name,
                    "repository": repo,
                    "tag": tag_info["name"],
                    "metadata": tag_info
                })
                
                if len(scan_queue) >= max_images:
                    break
            
            if len(scan_queue) >= max_images:
                break
        
        # Execute scans
        results = []
        for i, item in enumerate(scan_queue):
            logger.info(f"Scanning {item['image']} ({i+1}/{len(scan_queue)})")
            
            scan_result = run_scan(item["image"], enrich_cve=True)
            if "error" not in scan_result:
                scan_result.update({
                    "repository": item["repository"],
                    "tag": item["tag"],
                    "metadata": item["metadata"]
                })
                results.append(scan_result)
        
        return {
            "total_scanned": len(results),
            "total_queued": len(scan_queue),
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        }

# Initialize registry client
registry_client = DockerRegistryClient()

# ---------------- CVE DATABASE INTEGRATION ----------------
class CVEDatabase:
    """Handle CVE database operations and caching."""
    
    def __init__(self):
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_duration = timedelta(hours=24)
    
    async def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details with caching."""
        cached = cve_cache_collection.find_one({"cve_id": cve_id})
        if cached and datetime.utcnow() - cached["cached_at"] < self.cache_duration:
            logger.info(f"Using cached CVE data for {cve_id}")
            return cached["data"]
        
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
                        
                        cve_cache_collection.replace_one(
                            {"cve_id": cve_id},
                            {
                                "cve_id": cve_id,
                                "data": cve_data,
                                "cached_at": datetime.utcnow()
                            },
                            upsert=True
                        )
                        
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
        
        cvss_scores = {}
        metrics = vuln.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_scores["v3.1"] = {
                "score": cvss_v31.get("baseScore"),
                "severity": cvss_v31.get("baseSeverity"),
                "vector": cvss_v31.get("vectorString")
            }
        
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
            "cwe": [w.get("value") for w in vuln.get("weaknesses", [])]
        }
    
    async def enrich_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Enrich vulnerability data with CVE database information."""
        enriched = []
        semaphore = asyncio.Semaphore(5)
        
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
        logger.error("Trivy failed for %s: %s", image_name, str(e))
        return {"error": f"Trivy failed: {str(e)}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Trivy output for %s: %s", image_name, str(e))
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
        logger.info(f"Enriching {len(all_vulnerabilities)} vulnerabilities for {image_name}")
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            enriched_vulns = loop.run_until_complete(
                cve_db.enrich_vulnerabilities(all_vulnerabilities)
            )
            loop.close()
            
            vuln_index = 0
            for r in data.get("Results", []):
                if "Vulnerabilities" in r:
                    for i in range(len(r["Vulnerabilities"])):
                        if vuln_index < len(enriched_vulns):
                            r["Vulnerabilities"][i] = enriched_vulns[vuln_index]
                            vuln_index += 1
        except Exception as e:
            logger.error(f"CVE enrichment failed for {image_name}: {str(e)}")

    # Prepare document
    report_doc = {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report": data,
        "enriched": enrich_cve,
        "created_at": datetime.utcnow(),
        "scan_type": "single"
    }
    report_id = reports_collection.insert_one(report_doc).inserted_id

    # Send Slack notification
    send_slack_notification(image_name, elapsed, summary, str(report_id), enrich_cve)

    return {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report_id": str(report_id),
        "enriched": enrich_cve
    }

def send_slack_notification(image_name: str, elapsed: float, summary: dict, report_id: str, enriched: bool = False):
    """Send Slack notification with scan results."""
    if not SLACK_WEBHOOK_URL:
        return

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

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=10)
        if response.status_code == 200:
            logger.info("Slack notification sent for %s", image_name)
    except Exception as e:
        logger.error("Slack notification error: %s", str(e))

# ---------------- NEW REGISTRY ROUTES ----------------
@app.route("/registry/repositories", methods=["GET"])
def list_repositories():
    """List available repositories in configured registry."""
    try:
        repositories = registry_client.list_repositories()
        return jsonify({
            "registry_url": registry_client.registry_url,
            "repositories": repositories,
            "count": len(repositories)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/registry/repositories/<path:repository>/tags", methods=["GET"])
def list_repository_tags(repository):
    """List tags for a specific repository."""
    try:
        limit = int(request.args.get("limit", 50))
        tags = registry_client.list_image_tags(repository, limit)
        return jsonify({
            "repository": repository,
            "tags": tags,
            "count": len(tags)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/registry/scan", methods=["POST"])
def scan_registry():
    """Scan multiple images from registry."""
    try:
        data = request.get_json() or {}
        repositories = data.get("repositories", [])
        max_images = int(data.get("max_images", 50))
        
        if not repositories:
            # Default to popular repositories
            repositories = registry_client.list_repositories()[:10]
        
        logger.info(f"Starting registry scan for {len(repositories)} repositories")
        scan_results = registry_client.scan_registry_images(repositories, max_images)
        
        # Store registry scan summary
        registry_scan_doc = {
            "scan_type": "registry_batch",
            "repositories": repositories,
            "results": scan_results,
            "created_at": datetime.utcnow()
        }
        registry_scan_id = registry_cache_collection.insert_one(registry_scan_doc).inserted_id
        
        return jsonify({
            **scan_results,
            "registry_scan_id": str(registry_scan_id)
        })
        
    except Exception as e:
        logger.error(f"Registry scan error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/registry/scan/<scan_id>", methods=["GET"])
def get_registry_scan(scan_id):
    """Get registry scan results by ID."""
    try:
        scan = registry_cache_collection.find_one({"_id": ObjectId(scan_id)})
        if not scan:
            return jsonify({"error": "Registry scan not found"}), 404
        
        scan["_id"] = str(scan["_id"])
        return jsonify(scan)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- EXISTING ROUTES (Updated) ----------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Enhanced Container Registry Vulnerability Scanner",
        "version": "2.1",
        "features": [
            "Trivy Integration", 
            "CVE Database", 
            "MongoDB Storage", 
            "Slack Notifications",
            "Docker Registry Scanning",
            "Batch Image Processing"
        ],
        "routes": {
            "GET /registry/repositories": "List registry repositories",
            "GET /registry/repositories/<repo>/tags": "List repository tags",
            "POST /registry/scan": "Scan multiple registry images",
            "GET /registry/scan/<id>": "Get registry scan results",
            "POST /scan": "Single image scan",
            "GET /reports": "List all reports",
            "GET /stats": "Get statistics",
            "GET /health": "Health check"
        }
    })

@app.route("/health", methods=["GET"])
def health_check():
    """Enhanced health check including registry connectivity."""
    try:
        mongo_client.admin.command('ping')
        mongo_status = "healthy"
    except Exception as e:
        mongo_status = f"unhealthy: {str(e)}"
    
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        trivy_status = "healthy"
    except Exception as e:
        trivy_status = f"unhealthy: {str(e)}"
    
    # Check registry connectivity
    try:
        repositories = registry_client.list_repositories()
        registry_status = f"healthy ({len(repositories)} repos)"
    except Exception as e:
        registry_status = f"unhealthy: {str(e)}"
    
    status = {
        "status": "healthy" if all([
            mongo_status == "healthy", 
            trivy_status == "healthy"
        ]) else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "mongodb": mongo_status,
            "trivy": trivy_status,
            "docker_registry": registry_status,
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

@app.route("/reports", methods=["GET"])
def list_reports():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        scan_type = request.args.get("type", "all")  # single, registry_batch, all
        
        query = {}
        if scan_type != "all":
            query["scan_type"] = scan_type
            
        reports = reports_collection.find(
            query, 
            {"_id": 1, "image": 1, "created_at": 1, "summary": 1, "enriched": 1, "scan_type": 1}
        ).sort("created_at", -1).limit(limit)
        
        result = []
        for r in reports:
            result.append({
                "id": str(r["_id"]), 
                "image": r["image"], 
                "created_at": r["created_at"], 
                "summary": r.get("summary", {}), 
                "enriched": r.get("enriched", False),
                "scan_type": r.get("scan_type", "single")
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in list_reports: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/stats", methods=["GET"])
def get_stats():
    """Enhanced statistics including registry scans."""
    try:
        total_scans = reports_collection.count_documents({})
        single_scans = reports_collection.count_documents({"scan_type": "single"})
        registry_scans = registry_cache_collection.count_documents({})
        
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
        
        if "_id" in vuln_totals:
            del vuln_totals["_id"]
        
        return jsonify({
            "total_scans": total_scans,
            "single_image_scans": single_scans,
            "registry_batch_scans": registry_scans,
            "recent_scans_7d": recent_scans,
            "vulnerability_totals": vuln_totals,
            "cve_cache_size": cve_cache_collection.count_documents({}),
            "registry_url": registry_client.registry_url
        })
    except Exception as e:
        logger.error(f"Error in get_stats: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Include other existing routes (report fetching, CVE details, etc.)
@app.route("/report/<report_id>", methods=["GET"])
def get_report(report_id):
    try:
        report = reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            return jsonify({"error": "Report not found"}), 404
        
        report["_id"] = str(report["_id"])
        return jsonify(report)
    except Exception as e:
        return jsonify({"error": "Invalid report ID"}), 400

if __name__ == "__main__":
    logger.info("Starting Enhanced Container Registry Vulnerability Scanner v2.1")
    logger.info(f"MongoDB URI configured: {bool(MONGO_URI)}")
    logger.info(f"Slack webhook configured: {bool(SLACK_WEBHOOK_URL)}")
    logger.info(f"Registry URL: {registry_client.registry_url}")
    
    app.run(host="0.0.0.0", port=5000, debug=True)