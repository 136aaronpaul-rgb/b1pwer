"""
b1pwer.modules.active_directory - AD recon & BloodHound integration
"""
import subprocess
import re
from dataclasses import dataclass, field


@dataclass
class ADResult:
    domain: str = ""
    forest: str = ""
    dc: str = ""
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    computers: list = field(default_factory=list)
    trusts: list = field(default_factory=list)
    gpo_count: int = 0
    anonymous_users: bool = False
    anon_gid: bool = False


class ADScanner:
    def __init__(self):
        self.crackmapix = self._check("crackmapexec")
        self.enum4linux = self._check("enum4linux")
        self.bloodhound = self._check("bloodhound-python")

    def _check(self, cmd: str) -> bool:
        return subprocess.run(f"which {cmd} > /dev/null 2>&1", shell=True).returncode == 0

    def scan(self, target: str, username: str = "", password: str = "") -> ADResult:
        result = ADResult()
        creds = f"-u {username} -p {password}" if username else ""

        # Try crackmapexec
        if self.crackmapix:
            try:
                out = subprocess.run(
                    f"crackmapexec smb {target} {creds} --users 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=30
                ).stdout
                for line in out.split("\n"):
                    m = re.match(r'\s+\d+\s+(\S+)\s+(\S+)', line)
                    if m:
                        result.users.append(m.group(1))
            except:
                pass

            try:
                out = subprocess.run(
                    f"crackmapexec smb {target} {creds} --groups 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=30
                ).stdout
                for line in out.split("\n"):
                    m = re.match(r'\s+\d+\s+(\S+)\s+(\S+)', line)
                    if m:
                        result.groups.append(m.group(1))
            except:
                pass

            try:
                out = subprocess.run(
                    f"crackmapexec smb {target} {creds} --shares 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=30
                ).stdout
                m = re.search(r'\\(\\S+\\)', out)
                if m:
                    result.domain = m.group(1).replace("\\", "")
            except:
                pass

        # Try enum4linux
        if self.enum4linux:
            try:
                out = subprocess.run(
                    f"enum4linux -a {target} 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=60
                ).stdout
                m = re.search(r'Domain:\s*(\S+)', out)
                if m:
                    result.domain = m.group(1)
                m = re.search(r'Workgroup:\s*(\S+)', out)
                if m:
                    result.forest = m.group(1)
                for m in re.finditer(r'User name:\s*(\S+)', out):
                    if m.group(1) not in result.users:
                        result.users.append(m.group(1))
            except:
                pass

        # Nmap fallback
        try:
            out = subprocess.run(
                f"nmap -Pn -p 135,139,445,3268 --script=smb-enum-users,smb-enum-groups,smb-enum-sessions {target} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=30
            ).stdout
            for m in re.finditer(r'account:\s*(\S+)', out):
                if m.group(1) not in result.users:
                    result.users.append(m.group(1))
            for m in re.finditer(r'group:\s*(\S+)', out):
                if m.group(1) not in result.groups:
                    result.groups.append(m.group(1))
        except:
            pass

        return result

    def bloodhound_collect(self, target: str, username: str, password: str,
                           collection: str = "All") -> str:
        if not self.bloodhound:
            return "bloodhound-python not installed (pip install bloodhound)"
        try:
            result = subprocess.run(
                f"bloodhound-python -d {target} -u {username} -p {password} "
                f"-c {collection} -ns 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=120
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"
