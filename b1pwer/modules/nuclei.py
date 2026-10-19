"""
b1pwer.modules.nuclei - Nuclei vulnerability scanner integration
"""
import subprocess
import json
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    template_id: str
    name: str
    severity: str
    url: str
    port: int = 0
    cve: str = ""
    description: str = ""


class NucleiScanner:
    def __init__(self):
        self.nuclei_path = self._find_nuclei()
        self.available = self.nuclei_path is not None

    def _find_nuclei(self) -> Optional[str]:
        for path in ["/usr/local/bin/nuclei", "/usr/bin/nuclei", "nuclei"]:
            if os.path.isfile(path) or subprocess.run(
                f"which {path} > /dev/null 2>&1", shell=True
            ).returncode == 0:
                return path
        return None

    def scan(self, target: str, severity: str = "", tags: str = "",
             timeout: int = 300) -> list:
        """Run nuclei scan on target. Returns list of Finding objects."""
        if not self.available:
            return []

        cmd = [self.nuclei_path, "-u", target, "-jsonl", "-silent"]

        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    finding = Finding(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "info"),
                        url=data.get("matched-at", target),
                        port=data.get("host", "").split(":")[-1] if ":" in data.get("host", "") else 0,
                        cve=data.get("info", {}).get("reference", [""])[0].split("/")[-1] if data.get("info", {}).get("reference") else "",
                        description=data.get("info", {}).get("description", "")
                    )
                    findings.append(finding)
                except json.JSONDecodeError:
                    continue
            return findings
        except subprocess.TimeoutExpired:
            return []
        except Exception:
            return []

    def scan_with_file(self, targets_file: str, severity: str = "",
                       timeout: int = 600) -> list:
        """Scan multiple targets from a file."""
        if not self.available:
            return []

        cmd = [self.nuclei_path, "-l", targets_file, "-jsonl", "-silent"]
        if severity:
            cmd.extend(["-severity", severity])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    findings.append(Finding(
                        template_id=data.get("template-id", ""),
                        name=data.get("info", {}).get("name", ""),
                        severity=data.get("info", {}).get("severity", "info"),
                        url=data.get("matched-at", ""),
                        cve=data.get("info", {}).get("reference", [""])[0].split("/")[-1] if data.get("info", {}).get("reference") else "",
                        description=data.get("info", {}).get("description", "")
                    ))
                except json.JSONDecodeError:
                    continue
            return findings
        except Exception:
            return []
