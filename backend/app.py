#!/usr/bin/env python3
import os, subprocess, json, time
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import requests
from pymongo import MongoClient
from datetime import datetime

# Load environment variables
load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
MONGO_URI = os.getenv("MONGO_URI")

# Flask app
app = Flask(__name__)

# MongoDB setup
mongo_client = MongoClient(MONGO_URI)
db = mongo_client["vuln_scanner"]
reports_collection = db["reports"]

def run_scan(image_name):
    """Run Trivy scan and store report in MongoDB"""
    start_time = time.time()
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        return {"error": f"Trivy failed: {str(e)}"}

    data = json.loads(result.stdout)
    elapsed = round(time.time() - start_time, 2)

    # Count vulnerabilities
    summary = {"LOW":0, "MEDIUM":0, "HIGH":0, "CRITICAL":0}
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

    # Insert into MongoDB
    report_id = reports_collection.insert_one(report_doc).inserted_id

    # Slack notification
    if SLACK_WEBHOOK_URL:
        message = (
            f"*🔍 Scan Completed*\n"
            f"Image: `{image_name}`\n"
            f"Time: {elapsed} sec\n"
            f"Summary → LOW: {summary['LOW']}, MEDIUM: {summary['MEDIUM']}, "
            f"HIGH: {summary['HIGH']}, CRITICAL: {summary['CRITICAL']}\n"
            f"Report ID: `{report_id}`"
        )
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        except Exception as e:
            print(f"Slack notification failed: {e}")

    return {
        "image": image_name,
        "elapsed": elapsed,
        "summary": summary,
        "report_id": str(report_id)
    }

# ---------------- ROUTES ----------------

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "Vulnerability Scanner Backend",
        "routes": {
            "GET /reports": "List all report IDs",
            "GET /report/<id>": "Fetch specific report JSON",
            "POST /scan?image=<docker_image>": "Run scan on Docker image (API call)",
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
    from bson import ObjectId
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
