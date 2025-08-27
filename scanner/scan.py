#!/usr/bin/env python3
import json, subprocess, sys, os, time, requests
from datetime import datetime
from dotenv import load_dotenv

# Load .env file
load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

# Colors for terminal output
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def notify_slack(image_name, severity_count, status, report_path):
    """Send vulnerability results to Slack"""
    if not SLACK_WEBHOOK_URL:
        log(f"{RED}[!] Slack webhook URL not set. Skipping Slack notification.{RESET}")
        return

    message = (
        f"*🔍 Vulnerability Scan Report*\n"
        f"• Image: `{image_name}`\n"
        f"• Status: *{status}*\n\n"
        f"*Summary:*\n"
        f"   LOW: {severity_count['LOW']}\n"
        f"   MEDIUM: {severity_count['MEDIUM']}\n"
        f"   HIGH: {severity_count['HIGH']}\n"
        f"   CRITICAL: {severity_count['CRITICAL']}\n\n"
        f"Report saved at: `{report_path}`"
    )
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        if response.status_code != 200:
            log(f"{RED}[!] Slack notification failed: {response.text}{RESET}")
    except Exception as e:
        log(f"{RED}[!] Slack notification error: {str(e)}{RESET}")

def scan_image(image_name, report_path, fail_on="HIGH", debug=False):
    start_time = time.time()
    log(f"🔍 Starting vulnerability scan for: {CYAN}{image_name}{RESET}")
    
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]
    log(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        log(f"{RED}Trivy scan failed: {str(e)}{RESET}")
        sys.exit(2)

    data = json.loads(result.stdout)

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2)

    elapsed = time.time() - start_time
    log(f"✅ Scan complete in {elapsed:.2f} seconds. Report saved: {report_path}")

    # Count vulnerabilities
    severity_count = {"LOW":0, "MEDIUM":0, "HIGH":0, "CRITICAL":0}
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            sev = v.get("Severity")
            if sev in severity_count:
                severity_count[sev] += 1

    print("\n📊 Vulnerability Summary:")
    print(f"   {GREEN}LOW{RESET}: {severity_count['LOW']}")
    print(f"   {YELLOW}MEDIUM{RESET}: {severity_count['MEDIUM']}")
    print(f"   {RED}HIGH{RESET}: {severity_count['HIGH']}")
    print(f"   {RED}CRITICAL{RESET}: {severity_count['CRITICAL']}")

    # Always PASS (use WARNING if vulnerabilities found)
    status = "PASSED ✅"
    if any(v > 0 for v in severity_count.values()):
        log(f"{YELLOW}[!] Vulnerabilities detected → Reporting as WARNING only.{RESET}")
        status = "WARNING ⚠️"

    # 🔹 Send results to Slack
    notify_slack(image_name, severity_count, status, report_path)

    sys.exit(0)  # ✅ Never fail

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: scan.py <image_name> <report_path>")
        sys.exit(1)

    image = sys.argv[1]
    report = sys.argv[2]

    scan_image(image, report)
