#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for
import requests
import os

# Backend API URL
BACKEND_URL = os.getenv("BACKEND_URL", "http://172.30.0.123:5000")

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        image = request.form.get("image")
        if image:
            try:
                response = requests.post(f"{BACKEND_URL}/scan?image={image}")
                print(f"Backend response: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error connecting to backend: {e}")
            return redirect(url_for("index"))

    # Fetch reports list
    try:
        resp = requests.get(f"{BACKEND_URL}/reports")
        reports = resp.json() if resp.status_code == 200 else []
    except requests.exceptions.RequestException as e:
        print(f"Error fetching reports: {e}")
        reports = []
    
    return render_template("index.html", reports=reports)

@app.route("/scan", methods=["POST"])
def scan():
    """Handle scan requests - Alternative approach"""
    image = request.form.get("image")
    if image:
        try:
            response = requests.post(f"{BACKEND_URL}/scan?image={image}")
            print(f"Backend response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to backend: {e}")
    return redirect(url_for("index"))

@app.route("/report/<report_id>")
def report(report_id):
    try:
        resp = requests.get(f"{BACKEND_URL}/report/{report_id}")
        report_data = resp.json() if resp.status_code == 200 else {"error": "Report not found"}
    except requests.exceptions.RequestException as e:
        print(f"Error fetching report: {e}")
        report_data = {"error": "Could not connect to backend"}
    
    return render_template("report.html", report=report_data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)