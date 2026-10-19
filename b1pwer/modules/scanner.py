"""
b1pwer.scanner - Core scanning engine
"""
import nmap
import socket
import time
import json
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    device: str = ""


@dataclass
class HostResult:
    target: str
    ip: str
    hostname: str = ""
    os_guess: str = ""
    geo: str = ""
    org: str = ""
    asn: str = ""
    ports: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    web_info: dict = field(default_factory=dict)
    vulnerabilities: list = field(default_factory=list)
    scan_duration: float = 0.0
    scan_time: str = ""
    raw_nmap: dict = field(default_factory=dict)


class B1pwerScanner:
    SCAN_PROFILES = {
        "quick": {
            "ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,8080,8443",
            "args": "-Pn -T4",
            "description": "Top 19 common ports (~10s)"
        },
        "standard": {
            "ports": "1-1024",
            "args": "-Pn -sV -T4",
            "description": "All well-known ports + versions (~60s)"
        },
        "full": {
            "ports": "1-65535",
            "args": "-Pn -sV -sC -T4",
            "description": "All ports + version + default scripts (~5min)"
        },
        "aggressive": {
            "ports": "1-65535",
            "args": "-Pn -sV -sC -O -T3",
            "description": "All ports + version + scripts + OS (~10min)"
        },
        "vuln": {
            "ports": "1-65535",
            "args": "-Pn -sV -sC --script=vuln -T4",
            "description": "Full scan + vulnerability detection (~15min)"
        },
        "discovery": {
            "ports": "443,80",
            "args": "-sn",
            "description": "Host discovery only (ping scan)"
        },
    }

    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scanner.scanprogress = self._on_progress
        self.progress = 0.0

    def _on_progress(self, scan, host, result):
        self.progress = (scan.count / scan.total) * 100 if scan.total > 0 else 0

    def resolve(self, target: str) -> Optional[str]:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            try:
                socket.inet_aton(target)
                return target
            except:
                return None

    def get_ip_info(self, ip: str) -> dict:
        info = {"geo": "N/A", "org": "N/A", "asn": "N/A"}
        try:
            import ipwhois
            r = ipwhois.IPWhois()
            data = r.lookup(ip)
            info["geo"] = f"{data.get('city', '?')}, {data.get('country', '?')}"
            info["org"] = data.get('org', 'N/A')
            info["asn"] = str(data.get('asn', 'N/A'))
        except Exception:
            pass
        return info

    def get_dns(self, target: str) -> dict:
        records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "SOA": []}
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            for rtype in records.keys():
                try:
                    answers = resolver.resolve(target, rtype)
                    records[rtype] = [r.to_text() for r in answers]
                except:
                    pass
        except ImportError:
            import subprocess
            for rtype in records.keys():
                try:
                    out = subprocess.run(
                        f"dig +short {rtype} {target} 2>/dev/null",
                        shell=True, capture_output=True, text=True, timeout=10
                    ).stdout.strip()
                    if out:
                        records[rtype] = [l.strip() for l in out.split('\n') if l.strip()]
                except:
                    pass
        return records

    def get_web_info(self, ip: str, host: str = None) -> dict:
        import urllib.request
        import ssl
        import re
        info = {"http": False, "https": False, "server": "N/A",
                "title": "N/A", "headers": {}}
        for scheme in ["http", "https"]:
            url = f"{scheme}://{host or ip}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, method="HEAD")
                resp = urllib.request.urlopen(req, timeout=5, context=ctx)
                info[scheme] = True
                info["server"] = resp.headers.get("Server", "N/A")
                for key in ["X-Powered-By", "X-Frame-Options",
                           "Content-Security-Policy", "Strict-Transport-Security",
                           "X-Content-Type-Options", "X-XSS-Protection"]:
                    val = resp.headers.get(key)
                    if val:
                        info["headers"][key] = val
                req2 = urllib.request.Request(url)
                resp2 = urllib.request.urlopen(req2, timeout=5, context=ctx)
                html = resp2.read(10000).decode('utf-8', errors='ignore')
                title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
                if title_match:
                    info["title"] = title_match.group(1).strip()[:200]
                break
            except Exception:
                continue
        return info

    def scan(self, target: str, profile: str = "quick") -> HostResult:
        start_time = time.time()
        result = HostResult(target=target, ip="")
        ip = self.resolve(target)
        if not ip:
            raise ValueError(f"Cannot resolve target: {target}")
        result.ip = ip
        ip_info = self.get_ip_info(ip)
        result.geo = ip_info["geo"]
        result.org = ip_info["org"]
        result.asn = ip_info["asn"]
        profile_data = self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["quick"])
        self.scanner.scan(hosts=ip, ports=profile_data["ports"], arguments=profile_data["args"])
        for host in self.scanner.all_hosts():
            result.hostname = self.scanner[host].hostname()
            if "os" in self.scanner[host]:
                os_names = self.scanner[host]["os"].get("osmatch", [])
                if os_names:
                    result.os_guess = os_names[0].get("name", "")
            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto]:
                    p = self.scanner[host][proto][port]
                    if p["state"] != "open":
                        continue
                    result.ports.append(PortInfo(
                        port=port, protocol=proto, state=p["state"],
                        service=p.get("name", "unknown"),
                        version=p.get("version", ""),
                        device=p.get("device", "")
                    ))
                    scripts = p.get("scripts", {})
                    for script_name, script_data in scripts.items():
                        if any(k in script_name.lower() for k in ["vuln", "cve", "exploit", "ms17", "smb-vuln"]):
                            severity = "MEDIUM"
                            detail = str(script_data)
                            if "critical" in detail.lower() or "exploitable" in detail.lower():
                                severity = "CRITICAL"
                            elif "high" in detail.lower():
                                severity = "HIGH"
                            result.vulnerabilities.append({
                                "port": port, "script": script_name,
                                "severity": severity, "detail": detail[:500]
                            })
        result.dns_records = self.get_dns(target)
        result.web_info = self.get_web_info(ip, target)
        result.scan_duration = time.time() - start_time
        result.scan_time = datetime.now().isoformat()
        return result

    def scan_network(self, cidr: str, profile: str = "quick") -> list:
        results = []
        profile_data = self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["quick"])
        self.scanner.scan(hosts=cidr, ports=profile_data["ports"], arguments=profile_data["args"] + " -n")
        for host in self.scanner.all_hosts():
            if self.scanner[host].state() == "up":
                r = HostResult(target=host, ip=host, hostname=self.scanner[host].hostname())
                for proto in self.scanner[host].all_protocols():
                    for port in self.scanner[host][proto]:
                        p = self.scanner[host][proto][port]
                        if p["state"] != "open":
                            continue
                        r.ports.append(PortInfo(
                            port=port, protocol=proto, state=p["state"],
                            service=p.get("name", "unknown"), version=p.get("version", "")
                        ))
                results.append(r)
        return results
