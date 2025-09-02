#!/usr/bin/env python3
"""
Automated Registry Monitor
Monitors Docker registries for new pushes and automatically triggers vulnerability scans
"""
import os
import json
import time
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import requests
import schedule
from flask import Flask, request, jsonify

# Import existing components
from enhanced_backend_registry import (
    registry_client, run_scan, send_slack_notification, 
    reports_collection, db, logger
)

# Configuration
MONITOR_INTERVAL = int(os.getenv("MONITOR_INTERVAL_MINUTES", "5"))  # Check every 5 minutes
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "your-webhook-secret")
AUTO_SCAN_ENABLED = os.getenv("AUTO_SCAN_ENABLED", "true").lower() == "true"
MONITORED_REPOSITORIES = os.getenv("MONITORED_REPOSITORIES", "").split(",") if os.getenv("MONITORED_REPOSITORIES") else []

# Collections for tracking
registry_state_collection = db["registry_state"]
auto_scan_queue_collection = db["auto_scan_queue"]

class RegistryMonitor:
    """Monitors Docker registry for new image pushes and triggers scans."""
    
    def __init__(self):
        self.last_check = datetime.utcnow() - timedelta(hours=1)
        self.known_images: Set[str] = set()
        self.scan_queue: List[Dict] = []
        self.load_known_state()
    
    def load_known_state(self):
        """Load previously known registry state from database."""
        try:
            state = registry_state_collection.find_one({"_id": "registry_monitor_state"})
            if state:
                self.last_check = state.get("last_check", self.last_check)
                self.known_images = set(state.get("known_images", []))
                logger.info(f"Loaded registry state: {len(self.known_images)} known images")
            else:
                logger.info("No previous registry state found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading registry state: {str(e)}")
    
    def save_state(self):
        """Save current registry state to database."""
        try:
            registry_state_collection.replace_one(
                {"_id": "registry_monitor_state"},
                {
                    "_id": "registry_monitor_state",
                    "last_check": self.last_check,
                    "known_images": list(self.known_images),
                    "updated_at": datetime.utcnow()
                },
                upsert=True
            )
        except Exception as e:
            logger.error(f"Error saving registry state: {str(e)}")
    
    def get_user_repositories(self, username: str = "xxradeonfx") -> List[Dict]:
        """Get all repositories for a specific user."""
        try:
            # Use Docker Hub API to get user repositories
            url = f"https://hub.docker.com/v2/repositories/{username}/"
            params = {"page_size": 100}  # Get up to 100 repositories
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                repositories = []
                
                for repo in data.get("results", []):
                    repositories.append({
                        "name": repo["name"],
                        "full_name": repo["name"],  # For user repos, name is the same
                        "description": repo.get("description", ""),
                        "star_count": repo.get("star_count", 0),
                        "pull_count": repo.get("pull_count", 0),
                        "last_updated": repo.get("last_updated"),
                        "is_private": repo.get("is_private", False)
                    })
                
                logger.info(f"Found {len(repositories)} repositories for user {username}")
                return repositories
            else:
                logger.error(f"Failed to fetch repositories for {username}: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error fetching user repositories: {str(e)}")
            return []
    
    def get_repository_tags_with_metadata(self, repository: str, limit: int = 10) -> List[Dict]:
        """Get repository tags with detailed metadata including push timestamps."""
        try:
            url = f"https://hub.docker.com/v2/repositories/{repository}/tags"
            params = {"page_size": limit, "ordering": "-last_updated"}
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                tags = []
                
                for tag in data.get("results", []):
                    tags.append({
                        "name": tag["name"],
                        "full_name": f"{repository}:{tag['name']}",
                        "last_updated": tag.get("last_updated"),
                        "full_size": tag.get("full_size"),
                        "repository": repository,
                        "digest": tag.get("digest"),
                        "tag_last_pushed": tag.get("tag_last_pushed"),
                        "images": tag.get("images", [])
                    })
                
                return tags
            else:
                logger.warning(f"Failed to fetch tags for {repository}: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error fetching tags for {repository}: {str(e)}")
            return []
    
    def check_for_new_images(self) -> List[Dict]:
        """Check for newly pushed images since last check."""
        new_images = []
        current_check = datetime.utcnow()
        
        try:
            # Get all user repositories
            repositories = self.get_user_repositories("xxradeonfx")
            
            # If specific repositories are configured, filter to those
            if MONITORED_REPOSITORIES and MONITORED_REPOSITORIES[0]:  # Check if not empty string
                repo_names = [repo.get("name", repo.get("full_name", "")) for repo in repositories]
                repositories = [repo for repo in repositories if repo["name"] in MONITORED_REPOSITORIES]
                logger.info(f"Filtering to monitored repositories: {[r['name'] for r in repositories]}")
            
            for repo in repositories:
                repo_name = f"xxradeonfx/{repo['name']}"
                
                # Get recent tags for this repository
                tags = self.get_repository_tags_with_metadata(repo_name, limit=5)
                
                for tag_info in tags:
                    image_name = tag_info["full_name"]
                    last_updated = tag_info.get("last_updated")
                    
                    # Parse last_updated timestamp
                    if last_updated:
                        try:
                            updated_time = datetime.fromisoformat(last_updated.replace('Z', '+00:00')).replace(tzinfo=None)
                            
                            # Check if this image was updated since our last check
                            if (updated_time > self.last_check and 
                                image_name not in self.known_images):
                                
                                new_images.append({
                                    "image": image_name,
                                    "repository": repo_name,
                                    "tag": tag_info["name"],
                                    "last_updated": last_updated,
                                    "size": tag_info.get("full_size"),
                                    "detected_at": current_check.isoformat(),
                                    "scan_triggered": False
                                })
                                
                                # Add to known images
                                self.known_images.add(image_name)
                                
                                logger.info(f"New image detected: {image_name} (updated: {last_updated})")
                        
                        except Exception as e:
                            logger.error(f"Error parsing timestamp for {image_name}: {str(e)}")
            
            # Update last check time
            self.last_check = current_check
            self.save_state()
            
            return new_images
            
        except Exception as e:
            logger.error(f"Error checking for new images: {str(e)}")
            return []
    
    def queue_scan(self, image_info: Dict):
        """Add image to scan queue."""
        try:
            scan_doc = {
                **image_info,
                "queued_at": datetime.utcnow(),
                "status": "queued",
                "scan_id": None,
                "error": None
            }
            
            result = auto_scan_queue_collection.insert_one(scan_doc)
            logger.info(f"Queued scan for {image_info['image']}: {result.inserted_id}")
            return str(result.inserted_id)
            
        except Exception as e:
            logger.error(f"Error queuing scan: {str(e)}")
            return None
    
    def process_scan_queue(self):
        """Process pending scans in the queue."""
        try:
            # Get queued scans
            queued_scans = auto_scan_queue_collection.find({"status": "queued"}).limit(5)
            
            for scan_doc in queued_scans:
                try:
                    # Update status to processing
                    auto_scan_queue_collection.update_one(
                        {"_id": scan_doc["_id"]},
                        {"$set": {"status": "processing", "started_at": datetime.utcnow()}}
                    )
                    
                    # Execute scan
                    image_name = scan_doc["image"]
                    logger.info(f"Auto-scanning image: {image_name}")
                    
                    scan_result = run_scan(image_name, enrich_cve=True)
                    
                    if "error" in scan_result:
                        # Mark as failed
                        auto_scan_queue_collection.update_one(
                            {"_id": scan_doc["_id"]},
                            {
                                "$set": {
                                    "status": "failed",
                                    "error": scan_result["error"],
                                    "completed_at": datetime.utcnow()
                                }
                            }
                        )
                        logger.error(f"Auto-scan failed for {image_name}: {scan_result['error']}")
                    else:
                        # Mark as completed
                        auto_scan_queue_collection.update_one(
                            {"_id": scan_doc["_id"]},
                            {
                                "$set": {
                                    "status": "completed",
                                    "scan_id": scan_result["report_id"],
                                    "completed_at": datetime.utcnow()
                                }
                            }
                        )
                        
                        # Send enhanced notification for auto-discovered images
                        self.send_auto_scan_notification(scan_doc, scan_result)
                        logger.info(f"Auto-scan completed for {image_name}: {scan_result['report_id']}")
                
                except Exception as e:
                    # Mark as failed
                    auto_scan_queue_collection.update_one(
                        {"_id": scan_doc["_id"]},
                        {
                            "$set": {
                                "status": "failed",
                                "error": str(e),
                                "completed_at": datetime.utcnow()
                            }
                        }
                    )
                    logger.error(f"Error processing scan for {scan_doc['image']}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error processing scan queue: {str(e)}")
    
    def send_auto_scan_notification(self, scan_doc: Dict, scan_result: Dict):
        """Send enhanced Slack notification for automatically detected scans."""
        if not os.getenv("SLACK_WEBHOOK_URL"):
            return
        
        image_name = scan_doc["image"]
        summary = scan_result.get("summary", {})
        
        # Calculate risk
        risk_score = (summary.get("CRITICAL", 0) * 4 + summary.get("HIGH", 0) * 3 + 
                     summary.get("MEDIUM", 0) * 2 + summary.get("LOW", 0) * 1)
        
        risk_emoji = "🟢"
        risk_text = "LOW RISK"
        if risk_score > 100:
            risk_emoji = "🔴"
            risk_text = "CRITICAL RISK"
        elif risk_score > 50:
            risk_emoji = "🟠"
            risk_text = "HIGH RISK"
        elif risk_score > 20:
            risk_emoji = "🟡"
            risk_text = "MEDIUM RISK"
        
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🤖 Auto-Scan: New Image Detected!"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Image:*\n{image_name}"},
                    {"type": "mrkdwn", "text": f"*Pushed:*\n{scan_doc.get('last_updated', 'Unknown')}"},
                    {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk_emoji} {risk_text}"},
                    {"type": "mrkdwn", "text": f"*Scan Duration:*\n{scan_result.get('elapsed', 0)} sec"}
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
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🤖 *Automated Detection* | Report ID: `{scan_result.get('report_id', 'N/A')}` | Registry Monitor"
                    }
                ]
            }
        ]
        
        try:
            response = requests.post(
                os.getenv("SLACK_WEBHOOK_URL"),
                json={"blocks": blocks},
                timeout=10
            )
            if response.status_code == 200:
                logger.info(f"Auto-scan notification sent for {image_name}")
        except Exception as e:
            logger.error(f"Failed to send auto-scan notification: {str(e)}")
    
    def run_monitoring_cycle(self):
        """Run one complete monitoring cycle."""
        if not AUTO_SCAN_ENABLED:
            logger.debug("Auto-scan is disabled")
            return
        
        logger.info("Starting registry monitoring cycle...")
        
        # Check for new images
        new_images = self.check_for_new_images()
        
        if new_images:
            logger.info(f"Found {len(new_images)} new images")
            
            # Queue scans for new images
            for image_info in new_images:
                queue_id = self.queue_scan(image_info)
                if queue_id:
                    logger.info(f"Queued scan for {image_info['image']}: {queue_id}")
        
        # Process scan queue
        self.process_scan_queue()
        
        logger.info("Registry monitoring cycle completed")

# Initialize monitor
registry_monitor = RegistryMonitor()

def run_scheduled_monitoring():
    """Run monitoring on schedule."""
    registry_monitor.run_monitoring_cycle()

# Schedule monitoring
schedule.every(MONITOR_INTERVAL).minutes.do(run_scheduled_monitoring)

def monitoring_scheduler():
    """Background thread for running scheduled tasks."""
    while True:
        schedule.run_pending()
        time.sleep(30)  # Check every 30 seconds

# Start monitoring thread
monitoring_thread = threading.Thread(target=monitoring_scheduler, daemon=True)
monitoring_thread.start()

# Flask routes for monitoring management
def create_monitoring_app(main_app: Flask):
    """Add monitoring routes to the main Flask app."""
    
    @main_app.route("/monitor/status", methods=["GET"])
    def monitor_status():
        """Get monitoring status and statistics."""
        try:
            # Get queue statistics
            total_queued = auto_scan_queue_collection.count_documents({"status": "queued"})
            total_processing = auto_scan_queue_collection.count_documents({"status": "processing"})
            total_completed = auto_scan_queue_collection.count_documents({"status": "completed"})
            total_failed = auto_scan_queue_collection.count_documents({"status": "failed"})
            
            # Get recent activity
            recent_scans = list(auto_scan_queue_collection.find(
                {}, 
                {"_id": 1, "image": 1, "status": 1, "queued_at": 1, "completed_at": 1}
            ).sort("queued_at", -1).limit(10))
            
            for scan in recent_scans:
                scan["_id"] = str(scan["_id"])
            
            return jsonify({
                "monitoring_enabled": AUTO_SCAN_ENABLED,
                "check_interval_minutes": MONITOR_INTERVAL,
                "last_check": registry_monitor.last_check.isoformat(),
                "known_images_count": len(registry_monitor.known_images),
                "monitored_repositories": MONITORED_REPOSITORIES if MONITORED_REPOSITORIES[0] else ["all xxradeonfx repositories"],
                "queue_stats": {
                    "queued": total_queued,
                    "processing": total_processing,
                    "completed": total_completed,
                    "failed": total_failed
                },
                "recent_scans": recent_scans
            })
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @main_app.route("/monitor/trigger", methods=["POST"])
    def trigger_monitoring():
        """Manually trigger a monitoring cycle."""
        try:
            registry_monitor.run_monitoring_cycle()
            return jsonify({"message": "Monitoring cycle triggered successfully"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    @main_app.route("/monitor/webhook", methods=["POST"])
    def registry_webhook():
        """Handle Docker Hub webhooks for real-time notifications."""
        try:
            # Verify webhook (basic security)
            webhook_token = request.headers.get("X-Webhook-Token")
            if webhook_token != WEBHOOK_SECRET:
                return jsonify({"error": "Invalid webhook token"}), 401
            
            payload = request.get_json()
            
            # Parse Docker Hub webhook payload
            repository = payload.get("repository", {})
            repo_name = repository.get("repo_name", "")
            tag = payload.get("push_data", {}).get("tag", "")
            
            if repo_name and tag:
                image_name = f"{repo_name}:{tag}"
                
                # Queue immediate scan
                image_info = {
                    "image": image_name,
                    "repository": repo_name,
                    "tag": tag,
                    "last_updated": datetime.utcnow().isoformat(),
                    "detected_at": datetime.utcnow().isoformat(),
                    "trigger": "webhook"
                }
                
                queue_id = registry_monitor.queue_scan(image_info)
                logger.info(f"Webhook triggered scan for {image_name}: {queue_id}")
                
                return jsonify({
                    "message": f"Scan queued for {image_name}",
                    "queue_id": queue_id
                })
            else:
                return jsonify({"error": "Invalid webhook payload"}), 400
        
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
            return jsonify({"error": str(e)}), 500

logger.info("Registry monitoring system initialized")
logger.info(f"Auto-scan enabled: {AUTO_SCAN_ENABLED}")
logger.info(f"Check interval: {MONITOR_INTERVAL} minutes")
logger.info(f"Monitored repositories: {MONITORED_REPOSITORIES if MONITORED_REPOSITORIES[0] else 'all xxradeonfx repositories'}")