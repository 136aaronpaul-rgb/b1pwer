"""
b1pwer.modules.msf - Metasploit Framework integration
"""
import subprocess
import re
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MSFModule:
    name: str
    type: str
    description: str
    rank: str = ""
    reliability: str = ""


class MetasploitController:
    def __init__(self):
        self.available = self._check_msf()

    def _check_msf(self) -> bool:
        try:
            result = subprocess.run(
                "which msfconsole > /dev/null 2>&1", shell=True
            ).returncode
            return result == 0
        except:
            return False

    def search(self, query: str, timeout: int = 30) -> list:
        """Search Metasploit modules."""
        if not self.available:
            return []
        try:
            result = subprocess.run(
                f"msfconsole -q -x 'search {query}; back' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            modules = []
            for line in result.stdout.split("\n"):
                m = re.match(r'^\s*(\S+)\s{2,}(\w+)\s{2,}(\S+)\s{2,}(.+)$', line)
                if m:
                    modules.append(MSFModule(
                        name=m.group(1),
                        type=m.group(2),
                        rank=m.group(3),
                        description=m.group(4).strip()
                    ))
            return modules
        except:
            return []

    def search_by_cve(self, cve: str, timeout: int = 30) -> list:
        """Find Metasploit modules for a CVE."""
        return self.search(f"cve:{cve}", timeout)

    def search_by_service(self, service: str, timeout: int = 30) -> list:
        """Find modules for a service."""
        return self.search(f"service:{service}", timeout)

    def get_module_info(self, module: str, timeout: int = 30) -> dict:
        """Get detailed info about a module."""
        if not self.available:
            return {}
        try:
            result = subprocess.run(
                f"msfconsole -q -x 'show options {module}; info {module}; back' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            info = {"name": module, "options": [], "description": ""}
            for line in result.stdout.split("\n"):
                if line.strip().startswith("Name:") or line.strip().startswith("Description:"):
                    info["description"] = line.split(":", 1)[1].strip()
                m = re.match(r'^\s+(\S+)\s+(\S+)\s+(\w+)\s+(.+)$', line)
                if m and m.group(3) in ("true", "false"):
                    info["options"].append({
                        "name": m.group(1),
                        "type": m.group(2),
                        "required": m.group(3),
                        "default": m.group(4).strip()
                    })
            return info
        except:
            return {}

    def run_exploit(self, module: str, rhosts: str,
                    options: dict = None, timeout: int = 60) -> str:
        """Run a Metasploit exploit (requires user confirmation)."""
        if not self.available:
            return "Metasploit not available"

        cmds = [f"use exploit/{module}", f"set RHOSTS {rhosts}"]
        if options:
            for k, v in options.items():
                cmds.append(f"set {k} {v}")
        cmds.append("exploit -j")
        cmds.append("back")

        cmd_str = "; ".join(cmds)
        try:
            result = subprocess.run(
                f"msfconsole -q -x '{cmd_str}' 2>&1",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "Exploit timed out"
        except Exception as e:
            return f"Error: {e}"

    def list_listeners(self, timeout: int = 15) -> list:
        """List active Metasploit sessions/listeners."""
        if not self.available:
            return []
        try:
            result = subprocess.run(
                "msfconsole -q -x 'sessions; back' 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            sessions = []
            for line in result.stdout.split("\n"):
                m = re.match(r'^\s*(\d+)\s+(\S+)\s+(\S+)\s+(.+)$', line)
                if m:
                    sessions.append({
                        "id": m.group(1),
                        "type": m.group(2),
                        "info": m.group(3),
                        "details": m.group(4).strip()
                    })
            return sessions
        except:
            return []
