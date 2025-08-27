#!/usr/bin/env python3
import json, subprocess, sys, os, time, shutil
from datetime import datetime

# Colors for terminal
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def run_trivy(cmd):
    """Run Trivy with retries and handle DB update failures."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        if "mass scan has failed" in e.stderr or "database error" in e.stderr:
            log(f"{YELLOW}[!] Trivy DB update failed, retrying with --skip-update...{RESET}")
            cmd.insert(2, "--skip-update")
            return subprocess.run(cmd, capture_output=True, text=True, check=True)
        else:
            raise

def progress_bar(duration=10):
    """Fake progress bar for UX (like antivirus)."""
    steps = 30
    for i in range(steps + 1):
        done = "#" * i
        left = "-" * (steps - i)
        percent = (i / steps) * 100
        sys.stdout.write(f"\r{CYAN}Scanning: [{done}{left}] {percent:.1f}%{RESET}")
        sys.stdout.flush()
        time.sleep(duration / steps)
    print()

def scan_image(image_name, report_path, fail_on="HIGH", debug=False):
    start_time = time.time()
    log(f"🔍 Starting vulnerability scan for: {CYAN}{image_name}{RESET}")
    
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]
    log(f"Running command: {' '.join(cmd)}")

    # Show progress bar while scanning
    progress_bar(8)  # simulate scan time

    try:
        result = run_trivy(cmd)
    except Exception as e:
        log(f"{RED}Trivy scan failed: {str(e)}{RESET}")
        sys.exit(2)

    if debug:
        log("Raw Trivy output (first 300 chars):")
        print(result.stdout[:300] + "...\n")

    data = json.loads(result.stdout)

    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(data, f, indent=2)

    elapsed = time.time() - start_time
    log(f"✅ Scan complete in {elapsed:.2f} seconds. Report saved: {report_path}")

    # Count vulnerabilities by severity
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

    # Decide failing condition based on --fail-on threshold
    fail_levels = {
        "LOW": ["LOW","MEDIUM","HIGH","CRITICAL"],
        "MEDIUM": ["MEDIUM","HIGH","CRITICAL"],
        "HIGH": ["HIGH","CRITICAL"],
        "CRITICAL": ["CRITICAL"]
    }

    if any(severity_count[l] > 0 for l in fail_levels[fail_on]):
        log(f"{RED}[!] {fail_on}+ vulnerabilities detected → Scan FAILED.{RESET}")
        sys.exit(1)
    else:
        log(f"{GREEN}[+] No {fail_on}+ vulnerabilities. Scan PASSED.{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: scan.py <image_name> <report_path> [--fail-on <LOW|MEDIUM|HIGH|CRITICAL>] [--debug]")
        sys.exit(1)

    image = sys.argv[1]
    report = sys.argv[2]
    fail_on = "HIGH"
    debug = False

    if "--fail-on" in sys.argv:
        idx = sys.argv.index("--fail-on")
        fail_on = sys.argv[idx+1].upper()

    if "--debug" in sys.argv:
        debug = True

    scan_image(image, report, fail_on=fail_on, debug=debug)
