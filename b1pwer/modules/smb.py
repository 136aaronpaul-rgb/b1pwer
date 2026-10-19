"""
b1pwer.modules.smb - SMB and LDAP enumeration
"""
import subprocess
import re
from dataclasses import dataclass, field


@dataclass
class SMBResult:
    target: str
    domain: str = ""
    workgroup: str = ""
    os: str = ""
    server_name: str = ""
    users: list = field(default_factory=list)
    shares: list = field(default_factory=list)
    sessions: list = field(default_factory=list)
    sam_dump: str = ""


class SMBEnumerator:
    def enumerate(self, target: str) -> SMBResult:
        result = SMBResult(target=target)

        # Basic info
        try:
            out = subprocess.run(
                f"nmap -Pn -p 445 --script=smb-os-discovery,smb-system-info {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            m = re.search(r'netbios_name:\s*(\S+)', out)
            if m: result.server_name = m.group(1)
            m = re.search(r'domain:\s*(\S+)', out)
            if m: result.domain = m.group(1)
            m = re.search(r'workgroup:\s*(\S+)', out)
            if m: result.workgroup = m.group(1)
            m = re.search(r'os:\s*(.+)', out)
            if m: result.os = m.group(1).strip()
        except:
            pass

        # Users
        try:
            out = subprocess.run(
                f"nmap -Pn -p 445 --script=smb-enum-users {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            for m in re.finditer(r'account:\s*(\S+)', out):
                result.users.append(m.group(1))
        except:
            pass

        # Shares
        try:
            out = subprocess.run(
                f"nmap -Pn -p 445 --script=smb-enum-shares {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            for m in re.finditer(r'share_name:\s*(\S+)', out):
                result.shares.append(m.group(1))
        except:
            pass

        # Anonymous access check
        try:
            out = subprocess.run(
                f"nmap -Pn -p 445 --script=smb-enum-shares --script-args 'smb-enum-shares.username=,smb-enum-shares.password=' {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            if "accessible" in out.lower():
                result.shares.append("[ANONYMOUS ACCESS]")
        except:
            pass

        return result


class LDPEnumerator:
    def enumerate(self, target: str, port: int = 389) -> dict:
        result = {"target": target, "users": [], "groups": [], "domain": "", "error": ""}
        try:
            out = subprocess.run(
                f"nmap -Pn -p {port} --script=ldap-search {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            for m in re.finditer(r'cn:\s*(\S+)', out):
                result["users"].append(m.group(1))
            m = re.search(r'dc=\S+\.(\S+)', out)
            if m:
                result["domain"] = m.group(1)
        except:
            result["error"] = "LDAP not accessible"
        return result
