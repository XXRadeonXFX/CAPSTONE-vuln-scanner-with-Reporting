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

# Import all your classes here (DockerRegistryClient, CVEDatabase, etc.)