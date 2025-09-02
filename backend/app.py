#!/usr/bin/env python3
import os
import subprocess
import json
import time
import logging
import threading
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import asyncio
import aiohttp
import requests
from urllib.parse import urlparse

from flask import Flask, request, jsonify, abort
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import schedule

# ---------------- CONFIG ----------------
load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")
NVD_API_KEY = os.getenv("NVD_API_KEY")
DOCKER_REGISTRY_URL = os.getenv("DOCKER_REGISTRY_URL", "https://registry-1.docker.io")
DOCKER_USERNAME = os.getenv("DOCKER_USERNAME")
DOCKER_PASSWORD = os.getenv("DOCKER_PASSWORD")

# NEW: Automated Monitoring Configuration
AUTO_SCAN_ENABLED = os.getenv("AUTO_SCAN_ENABLED", "true").lower() == "true"
MONITOR_INTERVAL_MINUTES = int(os.getenv("MONITOR_INTERVAL_MINUTES", "5"))
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "your-secure-webhook-secret-change-this")
MONITORED_REPOSITORIES = os.getenv("MONITORED_REPOSITORIES", "").split(",") if os.getenv("MONITORED_REPOSITORIES") else []
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
SCAN_TIMEOUT_MINUTES = int(os.getenv("SCAN_TIMEOUT_MINUTES", "10"))
RETRY_FAILED_SCANS = os.getenv("RETRY_FAILED_SCANS", "true").lower() == "true"

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
monitoring_collection = db["monitoring"]
scan_queue_collection = db["scan_queue"]

# ---------------- DOCKER HUB API CLIENT ----------------
class DockerHubClient:
    """Enhanced Docker Hub API client for monitoring and webhooks."""
    
    def __init__(self):
        self.base_url = "https://hub.docker.com/v2"
        self.username = DOCKER_USERNAME
        self.password = DOCKER_PASSWORD
        self.token = None
        self.token_expires = None
        
    def authenticate(self):
        """Authenticate with Docker Hub and get access token."""
        try:
            auth_url = f"{self.base_url}/users/login/"
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            response = requests.post(auth_url, json=auth_data)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get("token")
                # Docker Hub tokens typically expire in 30 minutes
                self.token_expires = datetime.utcnow() + timedelta(minutes=25)
                logger.info("Docker Hub authentication successful")
                return True
            else:
                logger.error(f"Docker Hub auth failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Docker Hub authentication error: {str(e)}")
            return False
    
    def get_headers(self):
        """Get authenticated headers for API requests."""
        if not self.token or (self.token_expires and datetime.utcnow() > self.token_expires):
            if not self.authenticate():
                return {}
        
        return {
            "Authorization": f"JWT {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_user_repositories(self, page_size=100):
        """Get all repositories for the authenticated user."""
        repositories = []
        page = 1
        
        while True:
            try:
                url = f"{self.base_url}/repositories/{self.username}/"
                params = {"page": page, "page_size": page_size}
                headers = self.get_headers()
                
                response = requests.get(url, params=params, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    repos = data.get("results", [])
                    
                    for repo in repos:
                        repositories.append({
                            "name": repo["name"],
                            "namespace": repo["namespace"],
                            "full_name": f"{repo['namespace']}/{repo['name']}",
                            "description": repo.get("description", ""),
                            "last_updated": repo.get("last_updated"),
                            "pull_count": repo.get("pull_count", 0),
                            "star_count": repo.get("star_count", 0),
                            "is_private": repo.get("is_private", False)
                        })
                    
                    if not data.get("next"):
                        break
                    page += 1
                else:
                    logger.error(f"Failed to get repositories: {response.status_code}")
                    break
                    
            except Exception as e:
                logger.error(f"Error fetching repositories: {str(e)}")
                break
        
        return repositories
    
    def get_repository_tags(self, repository, limit=50):
        """Get tags for a specific repository with detailed information."""
        try:
            url = f"{self.base_url}/repositories/{repository}/tags/"
            params = {"page_size": limit, "ordering": "-last_updated"}
            headers = self.get_headers()
            
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data.get("results", [])
            else:
                logger.error(f"Failed to get tags for {repository}: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching tags for {repository}: {str(e)}")
            return []
    
    def check_for_new_pushes(self, repositories):
        """Check for new image pushes since last scan."""
        new_images = []
        
        for repo_name in repositories:
            try:
                # Get last scan time for this repository
                last_scan = monitoring_collection.find_one(
                    {"repository": repo_name},
                    sort=[("last_scan", -1)]
                )
                last_scan_time = last_scan["last_scan"] if last_scan else datetime.utcnow() - timedelta(days=7)
                
                # Get recent tags
                tags = self.get_repository_tags(repo_name, limit=10)
                
                for tag_info in tags:
                    tag_updated = datetime.fromisoformat(tag_info["last_updated"].replace('Z', '+00:00'))
                    
                    if tag_updated > last_scan_time:
                        image_name = f"{repo_name}:{tag_info['name']}"
                        new_images.append({
                            "image": image_name,
                            "repository": repo_name,
                            "tag": tag_info["name"],
                            "pushed_at": tag_updated,
                            "digest": tag_info.get("digest"),
                            "size": tag_info.get("full_size", 0)
                        })
                        
                        logger.info(f"New image detected: {image_name}")
                
                # Update last scan time
                monitoring_collection.update_one(
                    {"repository": repo_name},
                    {
                        "$set": {
                            "repository": repo_name,
                            "last_scan": datetime.utcnow(),
                            "status": "monitored"
                        }
                    },
                    upsert=True
                )
                
            except Exception as e:
                logger.error(f"Error checking {repo_name} for new pushes: {str(e)}")
                continue
        
        return new_images

# Initialize Docker Hub client
docker_hub_client = DockerHubClient()

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

# ---------------- SCAN QUEUE MANAGEMENT ----------------
class ScanQueue:
    """Manage scan queue with priority and retry logic."""
    
    def __init__(self):
        self.running_scans = 0
        self.max_concurrent = MAX_CONCURRENT_SCANS
        
    def add_to_queue(self, image_info, priority="normal", auto_triggered=True):
        """Add image to scan queue."""
        queue_item = {
            "image": image_info["image"],
            "repository": image_info.get("repository"),
            "tag": image_info.get("tag"),
            "priority": priority,  # high, normal, low
            "auto_triggered": auto_triggered,
            "queued_at": datetime.utcnow(),
            "attempts": 0,
            "status": "queued",  # queued, processing, completed, failed
            "metadata": image_info
        }
        
        scan_queue_collection.insert_one(queue_item)
        logger.info(f"Added {image_info['image']} to scan queue with {priority} priority")
    
    def get_next_scan(self):
        """Get next item from queue based on priority."""
        priority_order = ["high", "normal", "low"]
        
        for priority in priority_order:
            item = scan_queue_collection.find_one_and_update(
                {
                    "status": "queued",
                    "priority": priority
                },
                {
                    "$set": {
                        "status": "processing",
                        "started_at": datetime.utcnow()
                    },
                    "$inc": {"attempts": 1}
                },
                sort=[("queued_at", 1)]
            )
            if item:
                return item
        return None
    
    def mark_completed(self, queue_id, report_id):
        """Mark scan as completed."""
        scan_queue_collection.update_one(
            {"_id": queue_id},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow(),
                    "report_id": report_id
                }
            }
        )
    
    def mark_failed(self, queue_id, error_msg):
        """Mark scan as failed."""
        item = scan_queue_collection.find_one({"_id": queue_id})
        
        if item and item["attempts"] < 3 and RETRY_FAILED_SCANS:
            # Retry with exponential backoff
            retry_after = datetime.utcnow() + timedelta(minutes=2 ** item["attempts"])
            scan_queue_collection.update_one(
                {"_id": queue_id},
                {
                    "$set": {
                        "status": "queued",  # Back to queue for retry
                        "retry_after": retry_after,
                        "last_error": error_msg
                    }
                }
            )
            logger.info(f"Queued retry for scan {queue_id} after {item['attempts']} attempts")
        else:
            scan_queue_collection.update_one(
                {"_id": queue_id},
                {
                    "$set": {
                        "status": "failed",
                        "failed_at": datetime.utcnow(),
                        "error_message": error_msg
                    }
                }
            )
            logger.error(f"Scan {queue_id} permanently failed: {error_msg}")
    
    def cleanup_old_items(self, days=7):
        """Remove old completed/failed items from queue."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        result = scan_queue_collection.delete_many({
            "status": {"$in": ["completed", "failed"]},
            "$or": [
                {"completed_at": {"$lt": cutoff}},
                {"failed_at": {"$lt": cutoff}}
            ]
        })
        if result.deleted_count > 0:
            logger.info(f"Cleaned up {result.deleted_count} old queue items")

# Initialize scan queue
scan_queue = ScanQueue()

# ---------------- ENHANCED SCAN LOGIC ----------------
def run_scan(image_name: str, enrich_cve: bool = True, auto_triggered: bool = False) -> dict:
    """Run Trivy scan on a Docker image and store report in MongoDB."""
    start_time = time.time()
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]

    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True,
            timeout=SCAN_TIMEOUT_MINUTES * 60
        )
    except subprocess.CalledProcessError as e:
        logger.error("Trivy failed for %s: %s", image_name, str(e))
        return {"error": f"Trivy failed: {str(e)}"}
    except subprocess.TimeoutExpired:
        logger.error("Trivy timeout for %s", image_name)
        return {"error": f"Scan timeout after {SCAN_TIMEOUT_MINUTES} minutes"}

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
        "auto_triggered": auto_triggered,
        "created_at": datetime.utcnow(),
        "scan_type": "auto" if auto_triggered else "manual"
    }
    report_id = reports_collection.insert_one(report_doc).inserted_id

    # Send Slack notification
    send_slack_notification(image_name, elapsed, summary, str(report_id), enrich_cve, auto_triggered)

    return {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report_id": str(report_id),
        "enriched": enrich_cve,
        "auto_triggered": auto_triggered
    }

def send_slack_notification(image_name: str, elapsed: float, summary: dict, report_id: str, enriched: bool = False, auto_triggered: bool = False):
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

    scan_type_emoji = "🤖" if auto_triggered else "👤"
    scan_type_text = "Automatic Scan" if auto_triggered else "Manual Scan"

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{scan_type_emoji} {scan_type_text} Completed"}
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

    if auto_triggered:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"🔄 This scan was automatically triggered by a new image push"
                }
            ]
        })

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json={"blocks": blocks}, timeout=10)
        if response.status_code == 200:
            logger.info("Slack notification sent for %s", image_name)
    except Exception as e:
        logger.error("Slack notification error: %s", str(e))

# ---------------- AUTOMATED MONITORING ----------------
def monitor_and_scan():
    """Main monitoring function that runs periodically."""
    if not AUTO_SCAN_ENABLED:
        return
    
    logger.info("Starting automated monitoring cycle")
    
    try:
        # Determine which repositories to monitor
        repositories_to_monitor = MONITORED_REPOSITORIES if MONITORED_REPOSITORIES else []
        
        if not repositories_to_monitor:
            # Get all user repositories if none specified
            user_repos = docker_hub_client.get_user_repositories()
            repositories_to_monitor = [repo["full_name"] for repo in user_repos]
            logger.info(f"Monitoring all {len(repositories_to_monitor)} user repositories")
        else:
            logger.info(f"Monitoring specified repositories: {repositories_to_monitor}")
        
        # Check for new pushes
        new_images = docker_hub_client.check_for_new_pushes(repositories_to_monitor)
        
        if new_images:
            logger.info(f"Found {len(new_images)} new images to scan")
            
            # Add to scan queue
            for image_info in new_images:
                scan_queue.add_to_queue(image_info, priority="high", auto_triggered=True)
        else:
            logger.info("No new images found")
        
        # Process scan queue
        process_scan_queue()
        
        # Cleanup old queue items
        scan_queue.cleanup_old_items()
        
    except Exception as e:
        logger.error(f"Error in monitoring cycle: {str(e)}")

def process_scan_queue():
    """Process items in the scan queue."""
    while scan_queue.running_scans < scan_queue.max_concurrent:
        queue_item = scan_queue.get_next_scan()
        
        if not queue_item:
            break  # No more items to process
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=process_single_scan,
            args=(queue_item,)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        scan_queue.running_scans += 1

def process_single_scan(queue_item):
    """Process a single scan from the queue."""
    try:
        logger.info(f"Processing scan for {queue_item['image']}")
        
        scan_result = run_scan(
            queue_item["image"],
            enrich_cve=True,
            auto_triggered=queue_item.get("auto_triggered", True)
        )
        
        if "error" in scan_result:
            scan_queue.mark_failed(queue_item["_id"], scan_result["error"])
        else:
            scan_queue.mark_completed(queue_item["_id"], scan_result["report_id"])
        
    except Exception as e:
        logger.error(f"Error processing scan for {queue_item['image']}: {str(e)}")
        scan_queue.mark_failed(queue_item["_id"], str(e))
    finally:
        scan_queue.running_scans -= 1

# Schedule monitoring job
if AUTO_SCAN_ENABLED:
    schedule.every(MONITOR_INTERVAL_MINUTES).minutes.do(monitor_and_scan)
    logger.info(f"Scheduled monitoring every {MONITOR_INTERVAL_MINUTES} minutes")

def run_scheduler():
    """Run the scheduler in a background thread."""
    while True:
        try:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
        except Exception as e:
            logger.error(f"Scheduler error: {str(e)}")
            time.sleep(60)

# Start scheduler thread
if AUTO_SCAN_ENABLED:
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()

# ---------------- WEBHOOK ENDPOINTS ----------------
@app.route("/webhook/dockerhub", methods=["POST"])
def dockerhub_webhook():
    """Handle Docker Hub webhooks for immediate scanning."""
    try:
        # Verify webhook signature if secret is configured
        if WEBHOOK_SECRET:
            signature = request.headers.get("X-Hub-Signature")
            if not signature or not verify_webhook_signature(request.data, signature):
                abort(403)
        
        data = request.get_json()
        
        if data and "push_data" in data:
            repo_name = data["repository"]["repo_name"]
            tag = data["push_data"]["tag"]
            image_name = f"{repo_name}:{tag}"
            
            logger.info(f"Webhook received for {image_name}")
            
            # Add to high priority queue
            image_info = {
                "image": image_name,
                "repository": repo_name,
                "tag": tag,
                "pushed_at": datetime.utcnow(),
                "webhook_triggered": True
            }
            
            scan_queue.add_to_queue(image_info, priority="high", auto_triggered=True)
            
            # Try to process immediately if capacity available
            if scan_queue.running_scans < scan_queue.max_concurrent:
                process_scan_queue()
            
            return jsonify({
                "status": "success",
                "message": f"Scan queued for {image_name}",
                "queued_at": datetime.utcnow().isoformat()
            })
        
        return jsonify({"status": "ignored", "message": "Not a push event"})
        
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def verify_webhook_signature(payload, signature):
    """Verify Docker Hub webhook signature."""
    try:
        expected_signature = hmac.new(
            WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha1
        ).hexdigest()
        
        received_signature = signature.replace("sha1=", "")
        return hmac.compare_digest(expected_signature, received_signature)
    except Exception:
        return False

# ---------------- MONITORING API ENDPOINTS ----------------
@app.route("/monitoring/status", methods=["GET"])
def monitoring_status():
    """Get monitoring system status."""
    try:
        # Queue stats
        queue_stats = {
            "queued": scan_queue_collection.count_documents({"status": "queued"}),
            "processing": scan_queue_collection.count_documents({"status": "processing"}),
            "completed_today": scan_queue_collection.count_documents({
                "status": "completed",
                "completed_at": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            }),
            "failed_today": scan_queue_collection.count_documents({
                "status": "failed",
                "failed_at": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            })
        }
        
        # Monitoring stats
        monitored_repos = monitoring_collection.count_documents({"status": "monitored"})
        last_monitor_run = monitoring_collection.find_one(
            sort=[("last_scan", -1)]
        )
        
        return jsonify({
            "auto_scan_enabled": AUTO_SCAN_ENABLED,
            "monitor_interval_minutes": MONITOR_INTERVAL_MINUTES,
            "monitored_repositories": len(MONITORED_REPOSITORIES) if MONITORED_REPOSITORIES else "all",
            "queue_stats": queue_stats,
            "monitored_repos_count": monitored_repos,
            "last_monitor_run": last_monitor_run["last_scan"] if last_monitor_run else None,
            "running_scans": scan_queue.running_scans,
            "max_concurrent": scan_queue.max_concurrent
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/monitoring/repositories", methods=["GET"])
def get_monitored_repositories():
    """Get list of monitored repositories with their status."""
    try:
        monitored = list(monitoring_collection.find({}, {"_id": 0}))
        
        # Get Docker Hub repositories
        hub_repos = docker_hub_client.get_user_repositories()
        
        # Combine information
        result = []
        for repo in hub_repos:
            monitor_info = next(
                (m for m in monitored if m["repository"] == repo["full_name"]), 
                None
            )
            
            result.append({
                **repo,
                "monitored": bool(monitor_info),
                "last_scan": monitor_info["last_scan"] if monitor_info else None,
                "scan_status": monitor_info.get("status", "not_monitored") if monitor_info else "not_monitored"
            })
        
        return jsonify({
            "repositories": result,
            "total_count": len(result),
            "monitored_count": len(monitored)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/monitoring/repositories", methods=["POST"])
def update_monitored_repositories():
    """Update the list of monitored repositories."""
    try:
        data = request.get_json()
        repositories = data.get("repositories", [])
        
        if not repositories:
            return jsonify({"error": "No repositories specified"}), 400
        
        # Update monitoring collection
        for repo in repositories:
            monitoring_collection.update_one(
                {"repository": repo},
                {
                    "$set": {
                        "repository": repo,
                        "status": "monitored",
                        "updated_at": datetime.utcnow()
                    }
                },
                upsert=True
            )
        
        # Remove repositories not in the new list
        monitoring_collection.delete_many({
            "repository": {"$nin": repositories}
        })
        
        return jsonify({
            "message": f"Updated monitoring for {len(repositories)} repositories",
            "repositories": repositories
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/monitoring/trigger", methods=["POST"])
def trigger_manual_monitoring():
    """Manually trigger monitoring cycle."""
    try:
        # Run monitoring in background thread
        monitor_thread = threading.Thread(target=monitor_and_scan)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return jsonify({
            "message": "Monitoring cycle triggered manually",
            "triggered_at": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/queue/status", methods=["GET"])
def queue_status():
    """Get detailed scan queue status."""
    try:
        # Get queue items with pagination
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 20))
        status_filter = request.args.get("status")
        
        query = {}
        if status_filter:
            query["status"] = status_filter
        
        queue_items = list(scan_queue_collection.find(
            query,
            {"_id": 0}
        ).sort("queued_at", -1).skip((page - 1) * limit).limit(limit))
        
        total_count = scan_queue_collection.count_documents(query)
        
        # Convert datetime objects to strings for JSON serialization
        for item in queue_items:
            for field in ["queued_at", "started_at", "completed_at", "failed_at", "retry_after"]:
                if field in item and item[field]:
                    item[field] = item[field].isoformat()
        
        return jsonify({
            "items": queue_items,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_count,
                "has_next": (page * limit) < total_count,
                "has_prev": page > 1
            },
            "summary": {
                "queued": scan_queue_collection.count_documents({"status": "queued"}),
                "processing": scan_queue_collection.count_documents({"status": "processing"}),
                "completed": scan_queue_collection.count_documents({"status": "completed"}),
                "failed": scan_queue_collection.count_documents({"status": "failed"})
            }
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/queue/clear", methods=["POST"])
def clear_queue():
    """Clear completed and failed items from queue."""
    try:
        data = request.get_json() or {}
        statuses = data.get("statuses", ["completed", "failed"])
        
        result = scan_queue_collection.delete_many({
            "status": {"$in": statuses}
        })
        
        return jsonify({
            "message": f"Cleared {result.deleted_count} items from queue",
            "deleted_count": result.deleted_count,
            "cleared_statuses": statuses
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- ENHANCED EXISTING ROUTES ----------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Automated Container Registry Vulnerability Scanner",
        "version": "3.0",
        "features": [
            "Trivy Integration", 
            "CVE Database", 
            "MongoDB Storage", 
            "Slack Notifications",
            "Docker Registry Scanning",
            "Automated Monitoring",
            "Webhook Support",
            "Scan Queue Management"
        ],
        "monitoring": {
            "auto_scan_enabled": AUTO_SCAN_ENABLED,
            "monitor_interval": f"{MONITOR_INTERVAL_MINUTES} minutes",
            "monitored_repos": len(MONITORED_REPOSITORIES) if MONITORED_REPOSITORIES else "all user repositories",
            "webhook_endpoint": "/webhook/dockerhub"
        },
        "routes": {
            "GET /monitoring/status": "Get monitoring system status",
            "GET /monitoring/repositories": "List monitored repositories",
            "POST /monitoring/repositories": "Update monitored repositories",
            "POST /monitoring/trigger": "Manually trigger monitoring",
            "GET /queue/status": "Get scan queue status",
            "POST /queue/clear": "Clear completed queue items",
            "POST /webhook/dockerhub": "Docker Hub webhook endpoint",
            "POST /scan": "Manual image scan",
            "GET /reports": "List all reports",
            "GET /stats": "Get statistics",
            "GET /health": "Health check"
        }
    })

@app.route("/health", methods=["GET"])
def health_check():
    """Enhanced health check including monitoring system."""
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
    
    # Check Docker Hub connectivity
    try:
        repos = docker_hub_client.get_user_repositories()
        dockerhub_status = f"healthy ({len(repos)} repos accessible)"
    except Exception as e:
        dockerhub_status = f"unhealthy: {str(e)}"
    
    # Check monitoring system
    monitoring_status = "enabled" if AUTO_SCAN_ENABLED else "disabled"
    queue_size = scan_queue_collection.count_documents({"status": "queued"})
    
    status = {
        "status": "healthy" if all([
            mongo_status == "healthy", 
            trivy_status == "healthy"
        ]) else "unhealthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "mongodb": mongo_status,
            "trivy": trivy_status,
            "docker_hub": dockerhub_status,
            "monitoring_system": monitoring_status,
            "scan_queue_size": queue_size,
            "running_scans": scan_queue.running_scans,
            "slack_webhook": "configured" if SLACK_WEBHOOK_URL else "not configured",
            "nvd_api_key": "configured" if NVD_API_KEY else "not configured"
        },
        "monitoring_config": {
            "auto_scan_enabled": AUTO_SCAN_ENABLED,
            "monitor_interval_minutes": MONITOR_INTERVAL_MINUTES,
            "monitored_repositories": MONITORED_REPOSITORIES or "all",
            "max_concurrent_scans": MAX_CONCURRENT_SCANS,
            "webhook_secret_configured": bool(WEBHOOK_SECRET)
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
        result = run_scan(image, enrich_cve, auto_triggered=False)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in scan endpoint: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/reports", methods=["GET"])
def list_reports():
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
        scan_type = request.args.get("type", "all")  # manual, auto, all
        
        query = {}
        if scan_type != "all":
            query["scan_type"] = scan_type
            
        reports = reports_collection.find(
            query, 
            {"_id": 1, "image": 1, "created_at": 1, "summary": 1, "enriched": 1, "scan_type": 1, "auto_triggered": 1}
        ).sort("created_at", -1).limit(limit)
        
        result = []
        for r in reports:
            result.append({
                "id": str(r["_id"]), 
                "image": r["image"], 
                "created_at": r["created_at"], 
                "summary": r.get("summary", {}), 
                "enriched": r.get("enriched", False),
                "scan_type": r.get("scan_type", "manual"),
                "auto_triggered": r.get("auto_triggered", False)
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in list_reports: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/stats", methods=["GET"])
def get_stats():
    """Enhanced statistics including monitoring metrics."""
    try:
        total_scans = reports_collection.count_documents({})
        manual_scans = reports_collection.count_documents({"auto_triggered": False})
        auto_scans = reports_collection.count_documents({"auto_triggered": True})
        
        recent_scans = reports_collection.count_documents({
            "created_at": {"$gte": datetime.utcnow() - timedelta(days=7)}
        })
        
        recent_auto_scans = reports_collection.count_documents({
            "created_at": {"$gte": datetime.utcnow() - timedelta(days=7)},
            "auto_triggered": True
        })
        
        # Queue statistics
        queue_stats = {
            "queued": scan_queue_collection.count_documents({"status": "queued"}),
            "processing": scan_queue_collection.count_documents({"status": "processing"}),
            "completed_today": scan_queue_collection.count_documents({
                "status": "completed",
                "completed_at": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            }),
            "failed_today": scan_queue_collection.count_documents({
                "status": "failed",
                "failed_at": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            })
        }
        
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
            "manual_scans": manual_scans,
            "auto_scans": auto_scans,
            "recent_scans_7d": recent_scans,
            "recent_auto_scans_7d": recent_auto_scans,
            "vulnerability_totals": vuln_totals,
            "cve_cache_size": cve_cache_collection.count_documents({}),
            "monitored_repos": monitoring_collection.count_documents({}),
            "queue_stats": queue_stats,
            "monitoring_enabled": AUTO_SCAN_ENABLED,
            "dockerhub_username": DOCKER_USERNAME
        })
    except Exception as e:
        logger.error(f"Error in get_stats: {str(e)}")
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
        return jsonify({"error": "Invalid report ID"}), 400

if __name__ == "__main__":
    logger.info("Starting Automated Container Registry Vulnerability Scanner v3.0")
    logger.info(f"MongoDB URI configured: {bool(MONGO_URI)}")
    logger.info(f"Slack webhook configured: {bool(SLACK_WEBHOOK_URL)}")
    logger.info(f"Docker Hub username: {DOCKER_USERNAME}")
    logger.info(f"Auto-scan enabled: {AUTO_SCAN_ENABLED}")
    logger.info(f"Monitor interval: {MONITOR_INTERVAL_MINUTES} minutes")
    logger.info(f"Monitored repositories: {MONITORED_REPOSITORIES or 'all user repositories'}")
    
    # Run initial monitoring if enabled
    if AUTO_SCAN_ENABLED:
        initial_monitor_thread = threading.Thread(target=monitor_and_scan)
        initial_monitor_thread.daemon = True
        initial_monitor_thread.start()
        logger.info("Initial monitoring cycle started")
    
    app.run(host="0.0.0.0", port=5000, debug=True)