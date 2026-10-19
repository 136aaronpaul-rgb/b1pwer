"""
b1pwer.modules.dnszone - DNS zone transfer (AXFR) + DNS enumeration
"""
import subprocess
import socket
import re
from dataclasses import dataclass, field


@dataclass
class ZoneRecord:
    name: str
    rtype: str
    value: str


class DNSZoneScanner:
    def try_axfr(self, domain: str) -> list:
        """Attempt DNS zone transfer (AXFR)."""
        records = []
        for ns in self.get_nameservers(domain):
            try:
                result = subprocess.run(
                    f"dig axfr {domain} @{ns} 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split("\n"):
                    m = re.match(r'^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$', line.strip())
                    if m:
                        records.append(ZoneRecord(
                            name=m.group(1),
                            rtype=m.group(3),
                            value=m.group(4).strip()
                        ))
                if records:
                    break
            except:
                continue
        return records

    def get_nameservers(self, domain: str) -> list:
        try:
            result = subprocess.run(
                f"dig +short NS {domain} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout.strip()
            return [l.strip().rstrip('.') for l in result.split('\n') if l.strip()]
        except:
            return []

    def reverse_lookup(self, ip: str) -> str:
        """Reverse DNS: IP -> hostname."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""

    def brute_subdomains(self, domain: str, words: list = None) -> list:
        """Brute force subdomains with common wordlist."""
        if words is None:
            words = [
                "www", "mail", "ftp", "dev", "test", "staging",
                "api", "admin", "db", "blog", "shop", "app",
                "cdn", "static", "assets", "login", "portal",
                "vpn", "git", "wiki", "docs", "help", "status",
                "monitor", "grafana", "kibana", "jira", "confluence",
                "internal", "private", "secret", "backup", "old",
                "new", "beta", "alpha", "sandbox", "demo", "preview",
                "ns1", "ns2", "mx1", "mx2", "smtp", "pop", "imap",
                "web", "host", "server", "node", "cluster", "proxy",
                "load", "balance", "firewall", "router", "switch",
                "print", "scan", "share", "file", "data", "cloud"
            ]
        found = []
        for w in words:
            name = f"{w}.{domain}"
            try:
                ip = socket.gethostbyname(name) if True else ""
                found.append(ZoneRecord(name=name, rtype="A", value=ip))
            except:
                pass
        return found

    def scan(self, domain: str) -> dict:
        """Full DNS zone scan."""
        result = {
            "domain": domain,
            "nameservers": self.get_nameservers(domain),
            "axfr_success": False,
            "axfr_records": [],
            "brute_subdomains": [],
            "mx_records": [],
            "txt_records": []
        }

        # Try AXFR
        axfr = self.try_axfr(domain)
        if axfr:
            result["axfr_success"] = True
            result["axfr_records"] = axfr

        # MX records
        try:
            out = subprocess.run(
                f"dig +short MX {domain} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout.strip()
            result["mx_records"] = [l.strip() for l in out.split('\n') if l.strip()]
        except:
            pass

        # TXT records
        try:
            out = subprocess.run(
                f"dig +short TXT {domain} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout.strip()
            result["txt_records"] = [l.strip() for l in out.split('\n') if l.strip()]
        except:
            pass

        # Brute force subdomains
        result["brute_subdomains"] = []

        return result
