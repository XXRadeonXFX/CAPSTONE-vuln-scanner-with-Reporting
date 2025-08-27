#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for
import requests
import os

app = Flask(__name__)

# Backend API URL (adjust if backend runs on different host/port)
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        image = request.form.get("image")
        if image:
            # Trigger scan on backend
            res = requests.get(f"{BACKEND_URL}/scan", params={"image": image})
            if res.status_code == 200:
                return redirect(url_for("reports"))
    return render_template("index.html")

@app.route("/reports")
def reports():
    res = requests.get(f"{BACKEND_URL}/reports")
    reports = res.json() if res.status_code == 200 else []
    return render_template("reports.html", reports=reports)

@app.route("/report/<report_id>")
def report(report_id):
    res = requests.get(f"{BACKEND_URL}/report/{report_id}")
    report = res.json() if res.status_code == 200 else {"error": "Not found"}
    return render_template("report.html", report=report)
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
