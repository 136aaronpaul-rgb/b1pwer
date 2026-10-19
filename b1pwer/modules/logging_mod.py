"""
b1pwer.modules.logging_mod - Run logging to file
"""
import os
import json
from datetime import datetime


class B1pwerLogger:
    def __init__(self):
        self.log_dir = os.path.expanduser("~/.b1pwer/logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = os.path.join(
            self.log_dir, f"b1pwer_{datetime.now().strftime('%Y%m%d')}.log"
        )

    def log(self, level: str, module: str, message: str, data: dict = None):
        entry = {
            "time": datetime.now().isoformat(),
            "level": level,
            "module": module,
            "message": message
        }
        if data:
            entry["data"] = data
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def info(self, module: str, message: str, data: dict = None):
        self.log("INFO", module, message, data)

    def error(self, module: str, message: str, data: dict = None):
        self.log("ERROR", module, message, data)

    def scan_log(self, module: str, target: str, result: dict):
        self.log("SCAN", module, f"Scanned {target}", {
            "target": target,
            "ports": len(result.get("ports", [])),
            "vulns": len(result.get("vulns", [])),
            "duration": result.get("duration", 0)
        })

    def tail(self, lines: int = 20) -> list:
        if not os.path.isfile(self.log_file):
            return []
        with open(self.log_file, "r") as f:
            all_lines = f.readlines()
        entries = []
        for line in all_lines[-lines:]:
            try:
                entries.append(json.loads(line.strip()))
            except:
                pass
        return entries
