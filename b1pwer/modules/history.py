"""
b1pwer.modules.history - SQLite history database
Tracks all scans over time, enables comparison
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Optional


class HistoryDB:
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.expanduser("~/.b1pwer/history.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                ip TEXT,
                profile TEXT,
                timestamp TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                vulns TEXT,
                web_title TEXT,
                duration REAL,
                raw_json TEXT
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_target ON scans(target)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_time ON scans(timestamp)
        """)
        self.conn.commit()

    def save_scan(self, target: str, ip: str, profile: str,
                  ports: list, services: list, vulns: list,
                  web_title: str = "", duration: float = 0.0,
                  raw: dict = None):
        self.conn.execute(
            "INSERT INTO scans (target, ip, profile, timestamp, open_ports, services, vulns, web_title, duration, raw_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (target, ip, profile, datetime.now().isoformat(),
             json.dumps(ports), json.dumps(services), json.dumps(vulns),
             web_title, duration, json.dumps(raw) if raw else None)
        )
        self.conn.commit()

    def get_history(self, target: str = None, limit: int = 20) -> list:
        if target:
            rows = self.conn.execute(
                "SELECT id, target, ip, profile, timestamp, open_ports, vulns, duration FROM scans WHERE target=? ORDER BY timestamp DESC LIMIT ?",
                (target, limit)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT id, target, ip, profile, timestamp, open_ports, vulns, duration FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [
            {"id": r[0], "target": r[1], "ip": r[2], "profile": r[3],
             "time": r[4], "ports": json.loads(r[5] or "[]"),
             "vulns": json.loads(r[6] or "[]"), "duration": r[7]}
            for r in rows
        ]

    def compare(self, target: str) -> dict:
        """Compare last two scans of a target."""
        rows = self.conn.execute(
            "SELECT timestamp, open_ports, services, vulns FROM scans WHERE target=? ORDER BY timestamp DESC LIMIT 2",
            (target,)
        ).fetchall()
        if len(rows) < 2:
            return {"error": "Need at least 2 scans to compare"}
        newer, older = rows[0], rows[1]
        new_ports = set(json.loads(newer[1] or "[]"))
        old_ports = set(json.loads(older[1] or "[]"))
        new_vulns = json.loads(newer[3] or "[]")
        old_vulns = json.loads(older[3] or "[]")
        return {
            "target": target,
            "scan_1": older[0],
            "scan_2": newer[0],
            "new_ports": sorted(new_ports - old_ports),
            "closed_ports": sorted(old_ports - new_ports),
            "unchanged_ports": sorted(new_ports & old_ports),
            "new_vulns": [v for v in new_vulns if v not in old_vulns],
            "fixed_vulns": [v for v in old_vulns if v not in new_vulns]
        }

    def stats(self) -> dict:
        total = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        targets = self.conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
        vulns = self.conn.execute("SELECT COUNT(*) FROM scans WHERE vulns != '[]' AND vulns != ''").fetchone()[0]
        return {"total_scans": total, "unique_targets": targets, "scans_with_vulns": vulns}

    def close(self):
        self.conn.close()
