"""
b1pwer.modules.subdomains - Subdomain enumeration
"""
import subprocess
import socket
from dataclasses import dataclass, field

@dataclass
class Subdomain:
    name: str
    ip: str = ""
    status: str = "unknown"

class SubdomainScanner:
    def __init__(self):
        self.available = subprocess.run(
            "which subfinder > /dev/null 2>&1", shell=True
        ).returncode == 0

    def scan(self, domain: str, timeout: int = 60) -> list:
        subs = []
        if self.available:
            try:
                result = subprocess.run(
                    ["subfinder", "-d", domain, "-silent", "-all"],
                    capture_output=True, text=True, timeout=timeout
                )
                for line in result.stdout.strip().split("\n"):
                    line = line.strip()
                    if line:
                        subs.append(Subdomain(name=line, ip=self._resolve(line)))
            except:
                pass
        if not subs:
            subs = self._dns_guess(domain)
        return subs

    def _resolve(self, hostname: str) -> str:
        try:
            return socket.gethostbyname(hostname)
        except:
            return ""

    def _dns_guess(self, domain: str) -> list:
        guesses = ["www", "mail", "ftp", "dev", "test", "staging",
                   "api", "admin", "db", "blog", "shop", "app",
                   "cdn", "static", "assets", "login", "portal"]
        subs = []
        for g in guesses:
            name = f"{g}.{domain}"
            ip = self._resolve(name)
            if ip:
                subs.append(Subdomain(name=name, ip=ip, status="alive"))
        return subs
