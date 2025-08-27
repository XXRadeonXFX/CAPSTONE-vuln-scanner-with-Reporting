#!/usr/bin/env python3
import os
import subprocess
import json
import time
import logging
from datetime import datetime

from flask import Flask, request, jsonify
from dotenv import load_dotenv
from pymongo import MongoClient
from bson import ObjectId
import requests

# ---------------- CONFIG ----------------
load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")

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

# ---------------- SCAN LOGIC ----------------
def run_scan(image_name: str) -> dict:
    """Run Trivy scan on a Docker image and store report in MongoDB."""
    start_time = time.time()
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error("Trivy failed: %s", str(e))
        return {"error": f"Trivy failed: {str(e)}"}

    data = json.loads(result.stdout)
    elapsed = round(time.time() - start_time, 2)

    # Count vulnerabilities
    summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            sev = v.get("Severity")
            if sev in summary:
                summary[sev] += 1

    # Prepare document
    report_doc = {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report": data,
        "created_at": datetime.utcnow()
    }
    report_id = reports_collection.insert_one(report_doc).inserted_id

    # Send Slack notification (interactive)
    send_slack_notification(image_name, elapsed, summary, str(report_id))

    return {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report_id": str(report_id)
    }

# ---------------- SLACK ----------------
def send_slack_notification(image_name: str, elapsed: float, summary: dict, report_id: str):
    """Send an interactive Slack notification if webhook is configured."""
    if not SLACK_WEBHOOK_URL:
        logger.info("Slack webhook not set, skipping notification")
        return

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Vulnerability Scan Completed"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Image:*\n{image_name}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{elapsed} sec"},
                    {"type": "mrkdwn", "text": f"*Report ID:*\n{report_id}"}
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Vulnerability Summary*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*LOW:* {summary['LOW']}"},
                    {"type": "mrkdwn", "text": f"*MEDIUM:* {summary['MEDIUM']}"},
                    {"type": "mrkdwn", "text": f"*HIGH:* {summary['HIGH']}"},
                    {"type": "mrkdwn", "text": f"*CRITICAL:* {summary['CRITICAL']}"}
                ]
            }
        ]
    }

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload)
        if response.status_code != 200:
            logger.error("Slack notification failed: %s", response.text)
    except Exception as e:
        logger.error("Slack notification error: %s", str(e))

# ---------------- ROUTES ----------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Vulnerability Scanner Backend",
        "routes": {
            "GET /reports": "List all report IDs",
            "GET /report/<id>": "Fetch specific report JSON",
            "POST /scan?image=<docker_image>": "Run scan on Docker image",
            "GET /scan?image=<docker_image>": "Run scan (browser testing only)"
        }
    })

@app.route("/scan", methods=["GET", "POST"])
def scan():
    image = request.args.get("image")
    if not image:
        return jsonify({"error": "Please provide ?image=<docker_image>"}), 400
    return jsonify(run_scan(image))

@app.route("/reports", methods=["GET"])
def list_reports():
    reports = reports_collection.find({}, {"_id": 1, "image": 1, "created_at": 1})
    result = [{"id": str(r["_id"]), "image": r["image"], "created_at": r["created_at"]} for r in reports]
    return jsonify(result)

@app.route("/report/<report_id>", methods=["GET"])
def get_report(report_id):
    try:
        report = reports_collection.find_one({"_id": ObjectId(report_id)})
        if not report:
            return jsonify({"error": "Report not found"}), 404
        report["_id"] = str(report["_id"])
        return jsonify(report)
    except Exception:
        return jsonify({"error": "Invalid report ID"}), 400

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
