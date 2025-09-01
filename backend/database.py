#!/usr/bin/env python3
import os
import psycopg2
import psycopg2.extras
import json
from datetime import datetime
from typing import Dict, List, Optional

class PostgreSQLDatabase:
    def __init__(self):
        self.host = os.getenv("POSTGRES_HOST", "localhost")
        self.db = os.getenv("POSTGRES_DB", "cve_scanner")
        self.user = os.getenv("POSTGRES_USER", "postgres")
        self.password = os.getenv("POSTGRES_PASSWORD", "postgres")
        self.port = os.getenv("POSTGRES_PORT", "5432")
    
    def get_connection(self):
        return psycopg2.connect(
            dbname=self.db,
            user=self.user,
            password=self.password,
            host=self.host,
            port=self.port
        )
    
    def init_tables(self):
        """Initialize PostgreSQL tables for advanced reporting"""
        conn = self.get_connection()
        cur = conn.cursor()
        
        # Build reports table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS build_reports (
                id SERIAL PRIMARY KEY,
                project TEXT,
                image TEXT,
                tag TEXT,
                ci_url TEXT,
                full_report JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ai_recommendation TEXT DEFAULT NULL,
                ai_recommendation_html TEXT DEFAULT NULL
            )
        """)
        
        # Trivy results table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS trivy_results (
                id SERIAL PRIMARY KEY,
                build_id INT REFERENCES build_reports(id),
                severity TEXT,
                vuln_id TEXT,
                pkg_name TEXT,
                installed TEXT,
                fixed TEXT,
                status TEXT,
                primary_url TEXT,
                vendor_severity JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_exception INT DEFAULT 0
            )
        """)
        
        # Trivy secrets table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS trivy_secrets (
                id SERIAL PRIMARY KEY,
                build_id INT REFERENCES build_reports(id),
                target TEXT,
                rule_id TEXT,
                category TEXT,
                severity TEXT,
                title TEXT,
                start_line INT,
                end_line INT,
                match TEXT,
                code JSONB,
                layer JSONB,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        cur.close()
        conn.close()
    
    def save_scan_report(self, scan_data: dict, project: str, image: str, tag: str, ci_url: str = None) -> int:
        """Save scan report to PostgreSQL and return build_id"""
        conn = self.get_connection()
        cur = conn.cursor()
        
        # Insert build report
        cur.execute("""
            INSERT INTO build_reports (project, image, tag, ci_url, full_report, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id
        """, (project, image, tag, ci_url, json.dumps(scan_data), datetime.utcnow()))
        
        build_id = cur.fetchone()[0]
        
        # Load exceptions
        exceptions = self._load_exceptions()
        
        # Process vulnerabilities
        for result in scan_data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []) or []:
                vuln_id = vuln.get("VulnerabilityID")
                is_exception = 1 if vuln_id in exceptions else 0
                
                cur.execute("""
                    INSERT INTO trivy_results (build_id, severity, vuln_id, pkg_name, installed, fixed,
                                             status, primary_url, vendor_severity, timestamp, is_exception)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    build_id, vuln.get("Severity"), vuln_id, vuln.get("PkgName"),
                    vuln.get("InstalledVersion"), vuln.get("FixedVersion"),
                    vuln.get("Status"), vuln.get("PrimaryURL"),
                    json.dumps(vuln.get("VendorSeverity", {})),
                    datetime.utcnow(), is_exception
                ))
            
            # Process secrets if present
            if result.get("Class") == "secret":
                target = result.get("Target")
                for secret in result.get("Secrets", []):
                    cur.execute("""
                        INSERT INTO trivy_secrets (build_id, target, rule_id, category, severity, title,
                                                start_line, end_line, match, code, layer, timestamp)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """, (
                        build_id, target, secret.get("RuleID"), secret.get("Category"),
                        secret.get("Severity"), secret.get("Title"),
                        secret.get("StartLine"), secret.get("EndLine"),
                        secret.get("Match"),
                        json.dumps(secret.get("Code")) if secret.get("Code") else None,
                        json.dumps(secret.get("Layer")) if secret.get("Layer") else None,
                        datetime.utcnow()
                    ))
        
        conn.commit()
        cur.close()
        conn.close()
        return build_id
    
    def _load_exceptions(self) -> set:
        """Load vulnerability exceptions from file"""
        exceptions_file = os.path.join(os.path.dirname(__file__), "exceptions.txt")
        try:
            with open(exceptions_file) as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

# Initialize database instance
postgres_db = PostgreSQLDatabase()