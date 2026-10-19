"""
b1pwer.modules.cve - CVE database lookup and exploit matching
"""
import json
import os
import subprocess
import urllib.request
import ssl
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEInfo:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    cwe: str = ""
    affected: str = ""
    exploit_available: bool = False
    exploit_db_id: str = ""
    metasploit_module: str = ""
    references: list = field(default_factory=list)


class CVELookup:
    def __init__(self):
        self.cache_path = os.path.expanduser("~/.b1pwer/cve_cache.json")
        self.cache = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.isfile(self.cache_path):
            try:
                with open(self.cache_path, "r") as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}

    def _save_cache(self):
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        with open(self.cache_path, "w") as f:
            json.dump(self.cache, f)

    def lookup(self, cve_id: str) -> Optional[CVEInfo]:
        if cve_id in self.cache:
            return self._from_cache(self.cache[cve_id])
        data = self._fetch_nvd(cve_id)
        if data:
            self.cache[cve_id] = data
            self._save_cache()
            return self._from_cache(data)
        return None

    def lookup_by_service(self, service: str, version: str = "") -> list:
        """Find CVEs for a service/version."""
        results = []
        query = f"{service}"
        if version:
            query += f" {version}"
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=20"
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "b1pwer/1.0"})
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            data = json.loads(resp.read().decode())
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                score = 0.0
                severity = "UNKNOWN"
                metrics = cve.get("metrics", {})
                if "cvssMetricV31" in metrics:
                    data31 = metrics["cvssMetricV31"][0].get("cvssData", {})
                    score = data31.get("baseScore", 0)
                    severity = metrics["cvssMetricV31"][0].get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV30" in metrics:
                    data30 = metrics["cvssMetricV30"][0].get("cvssData", {})
                    score = data30.get("baseScore", 0)
                    severity = metrics["cvssMetricV30"][0].get("baseSeverity", "UNKNOWN")
                results.append(CVEInfo(
                    cve_id=cve_id, cvss_score=score, severity=severity,
                    description=desc[:200]
                ))
        except:
            pass
        return results[:10]

    def find_exploits(self, cve_id: str) -> dict:
        """Check Exploit-DB and Metasploit for available exploits."""
        result = {"exploit_available": False, "exploit_db_id": "", "metasploit_module": ""}
        # Check Exploit-DB
        try:
            url = f"https://www.exploit-db.com/search?text={cve_id}"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            html = resp.read().decode(errors="ignore")
            if f"exploits/{cve_id}" in html or cve_id in html:
                result["exploit_available"] = True
                import re
                match = re.search(r'exploits/(\d+)', html)
                if match:
                    result["exploit_db_id"] = match.group(1)
        except:
            pass
        # Check Metasploit
        try:
            result2 = subprocess.run(
                f"msfconsole -q -x 'search cve:{cve_id}; back' 2>/dev/null | grep -oP 'multi/(attack|exploit)/\\S+|linux/(exploit)/\\S+'",
                shell=True, capture_output=True, text=True, timeout=15
            )
            if result2.stdout.strip():
                result["exploit_available"] = True
                result["metasploit_module"] = result2.stdout.strip().split("\n")[0]
        except:
            pass
        return result

    def _fetch_nvd(self, cve_id: str) -> Optional[dict]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "b1pwer/1.0"})
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            data = json.loads(resp.read().decode())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None
            cve = vulns[0].get("cve", {})
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score = 0.0
            severity = "UNKNOWN"
            metrics = cve.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    m = metrics[key][0]
                    score = m.get("cvssData", {}).get("baseScore", 0)
                    severity = m.get("baseSeverity", "UNKNOWN")
                    break
            cwe = ""
            weaknesses = cve.get("weaknesses", [])
            if weaknesses:
                desc_list = weaknesses[0].get("description", [])
                if desc_list:
                    cwe = desc_list[0].get("value", "")
            refs = []
            for r in cve.get("references", [])[:5]:
                refs.append(r.get("url", ""))
            return {
                "cve_id": cve_id, "cvss_score": score,
                "severity": severity, "description": desc[:500],
                "cwe": cwe, "references": refs
            }
        except:
            return None

    def _from_cache(self, data: dict) -> CVEInfo:
        return CVEInfo(
            cve_id=data.get("cve_id", ""),
            cvss_score=data.get("cvss_score", 0),
            severity=data.get("severity", "UNKNOWN"),
            description=data.get("description", ""),
            cwe=data.get("cwe", ""),
            references=data.get("references", [])
        )

    def lookup_batch(self, cve_ids: list) -> list:
        results = []
        for cid in cve_ids:
            info = self.lookup(cid)
            if info:
                results.append(info)
        return results
