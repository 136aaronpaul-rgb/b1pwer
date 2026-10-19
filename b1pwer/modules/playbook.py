"""
b1pwer.modules.playbook - One-command full assessment
Chains all modules together into a single automated workflow
"""
import time
import json
import os
from datetime import datetime
from typing import Optional


class Playbook:
    """
    b1pwer --playbook <target>
    
    One command that:
    1. Resolves target
    2. Scans all TCP ports
    3. Scans UDP ports
    4. Grabs banners
    5. Enumerates subdomains
    6. Audits SSL
    7. Checks DNS zone
    8. Runs Nuclei
    9. Looks up CVEs
    10. Suggests exploits
    11. Scans for cloud misconfigs
    12. Discovers API endpoints
    13. Generates combined report (HTML + JSON + PDF)
    14. Saves to history
    15. Sends alerts for critical findings
    """

    def __init__(self, output_dir: str = "./b1pwer_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {}
        self.alerts = []

    def run(self, target: str, profile: str = "standard",
            run_nuclei: bool = True, run_cloud: bool = True,
            run_api: bool = True, verbose: bool = True) -> dict:
        start = time.time()
        self.results = {
            "target": target,
            "start_time": datetime.now().isoformat(),
            "modules_run": [],
            "modules_failed": []
        }

        if verbose:
            print(f"\n  [1/12] Resolving target...")
        self._resolve(target)

        if verbose:
            print(f"  [2/12] Port scan (TCP)...")
        self._scan_tcp(target, profile)

        if verbose:
            print(f"  [3/12] Port scan (UDP)...")
        self._scan_udp(target)

        if verbose:
            print(f"  [4/12] Banner grabbing...")
        self._grab_banners(target)

        if verbose:
            print(f"  [5/12] Subdomain enumeration...")
        self._scan_subdomains(target)

        if verbose:
            print(f"  [6/12] SSL/TLS audit...")
        self._audit_ssl(target)

        if verbose:
            print(f"  [7/12] DNS zone check...")
        self._check_dns_zone(target)

        if run_nuclei:
            if verbose:
                print(f"  [8/12] Nuclei scan (10k+ templates)...")
            self._run_nuclei(target)
        else:
            if verbose:
                print(f"  [8/12] Nuclei (skipped)")

        if verbose:
            print(f"  [9/12] CVE lookup...")
        self._lookup_cves()

        if verbose:
            print(f"  [10/12] Exploit suggestions...")
        self._suggest_exploits()

        if run_cloud:
            if verbose:
                print(f"  [11/12] Cloud scan...")
            self._scan_cloud(target)
        else:
            if verbose:
                print(f"  [11/12] Cloud (skipped)")

        if run_api:
            if verbose:
                print(f"  [12/12] API discovery...")
            self._discover_api(target)
        else:
            if verbose:
                print(f"  [12/12] API (skipped)")

        if verbose:
            print(f"\n  Generating reports...")
        self._generate_reports()

        self.results["duration"] = round(time.time() - start, 2)
        self.results["end_time"] = datetime.now().isoformat()

        if verbose:
            self._print_summary()

        return self.results

    def _resolve(self, target: str):
        import socket
        try:
            ip = socket.gethostbyname(target)
            self.results["ip"] = ip
            self.results["modules_run"].append("resolve")
        except:
            self.results["ip"] = target
            self.results["modules_run"].append("resolve")

    def _scan_tcp(self, target: str, profile: str):
        try:
            from .scanner import B1pwerScanner
            scanner = B1pwerScanner()
            result = scanner.scan(target, profile)
            self.results["tcp_ports"] = [
                {"port": p.port, "service": p.service, "version": p.version}
                for p in result.ports
            ]
            self.results["os_guess"] = result.os_guess
            self.results["web_info"] = result.web_info
            self.results["dns_records"] = result.dns_records
            self.results["vulns_nmap"] = result.vulnerabilities
            self.results["modules_run"].append("tcp_scan")
        except Exception as e:
            self.results["modules_failed"].append(f"tcp_scan: {e}")

    def _scan_udp(self, target: str):
        try:
            from .udp import UDPScanner
            us = UDPScanner()
            results = us.scan(target)
            self.results["udp_ports"] = [
                {"port": r.port, "state": r.state, "service": r.service}
                for r in results if r.state in ("open", "open|filtered")
            ]
            self.results["modules_run"].append("udp_scan")
        except Exception as e:
            self.results["modules_failed"].append(f"udp_scan: {e}")

    def _grab_banners(self, target: str):
        try:
            from .banner import BannerGrabber
            bg = BannerGrabber()
            results = bg.grab(target)
            self.results["banners"] = [
                {"port": r.port, "service": r.service, "version": r.version, "os": r.os_hint}
                for r in results
            ]
            self.results["modules_run"].append("banner")
        except Exception as e:
            self.results["modules_failed"].append(f"banner: {e}")

    def _scan_subdomains(self, target: str):
        try:
            from .subdomains import SubdomainScanner
            ss = SubdomainScanner()
            subs = ss.scan(target)
            self.results["subdomains"] = [
                {"name": s.name, "ip": s.ip} for s in subs[:50]
            ]
            self.results["modules_run"].append("subdomains")
        except Exception as e:
            self.results["modules_failed"].append(f"subdomains: {e}")

    def _audit_ssl(self, target: str):
        try:
            from .ssl import SSLScanner
            sa = SSLScanner()
            result = sa.audit(target)
            self.results["ssl"] = {
                "protocol": result.protocol,
                "key_size": result.key_size,
                "days_remaining": result.days_remaining,
                "score": result.score
            }
            self.results["modules_run"].append("ssl")
        except Exception as e:
            self.results["modules_failed"].append(f"ssl: {e}")

    def _check_dns_zone(self, target: str):
        try:
            from .dnszone import DNSZoneScanner
            dz = DNSZoneScanner()
            result = dz.scan(target)
            self.results["dns_zone"] = {
                "axfr_open": result["axfr_success"],
                "nameservers": result["nameservers"],
                "mx": result["mx_records"]
            }
            self.results["modules_run"].append("dns_zone")
        except Exception as e:
            self.results["modules_failed"].append(f"dns_zone: {e}")

    def _run_nuclei(self, target: str):
        try:
            from .nuclei import NucleiScanner
            nuclei = NucleiScanner()
            if nuclei.available:
                findings = nuclei.scan(target)
                self.results["nuclei"] = [
                    {"id": f.template_id, "name": f.name, "severity": f.severity, "cve": f.cve}
                    for f in findings
                ]
                self.results["modules_run"].append("nuclei")
            else:
                self.results["modules_failed"].append("nuclei: not installed")
        except Exception as e:
            self.results["modules_failed"].append(f"nuclei: {e}")

    def _lookup_cves(self):
        try:
            from .cve import CVELookup
            cl = CVELookup()
            cves_found = set()
            for v in self.results.get("vulns_nmap", []):
                if "CVE" in v.get("script", "").upper():
                    cves_found.add(v["script"])
            for f in self.results.get("nuclei", []):
                if f.get("cve"):
                    cves_found.add(f["cve"])
            cve_details = []
            for cve in list(cves_found)[:10]:
                info = cl.lookup(cve)
                if info:
                    cve_details.append({
                        "id": info.cve_id, "score": info.cvss_score,
                        "severity": info.severity, "desc": info.description[:100]
                    })
            self.results["cves"] = cve_details
            self.results["modules_run"].append("cve_lookup")
        except Exception as e:
            self.results["modules_failed"].append(f"cve_lookup: {e}")

    def _suggest_exploits(self):
        try:
            from .exploit import ExploitSuggester
            es = ExploitSuggester()
            class FakePort:
                def __init__(self, d):
                    self.port = d["port"]
                    self.service = d.get("service", "")
                    self.version = d.get("version", "")
            ports = [FakePort(p) for p in self.results.get("tcp_ports", [])]
            suggestions = es.suggest(ports)
            self.results["exploits"] = [
                {"port": s.port, "cve": s.cve, "severity": s.severity, "msf": s.msf_module}
                for s in suggestions
            ]
            self.results["modules_run"].append("exploit_suggest")
        except Exception as e:
            self.results["modules_failed"].append(f"exploit_suggest: {e}")

    def _scan_cloud(self, target: str):
        try:
            from .cloud import CloudScanner
            cs = CloudScanner()
            findings = cs.full_scan(target)
            self.results["cloud"] = [
                {"provider": f.provider, "resource": f.resource, "issue": f.issue, "severity": f.severity}
                for f in findings
            ]
            self.results["modules_run"].append("cloud")
        except Exception as e:
            self.results["modules_failed"].append(f"cloud: {e}")

    def _discover_api(self, target: str):
        try:
            from .api import APIDiscoverer
            ad = APIDiscoverer()
            results = ad.scan(target)
            self.results["api_endpoints"] = [
                {"path": e.path, "status": e.status, "reason": e.reason}
                for e in results if e.interesting
            ]
            self.results["modules_run"].append("api_discovery")
        except Exception as e:
            self.results["modules_failed"].append(f"api_discovery: {e}")

    def _generate_reports(self):
        from .reporter import Reporter
        from .pdf import PDFReporter

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = self.results["target"].replace(".", "_").replace("/", "_")

        # JSON
        json_path = os.path.join(self.output_dir, f"b1pwer_playbook_{safe}_{ts}.json")
        with open(json_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        self.results["report_json"] = json_path

        # HTML
        html_path = os.path.join(self.output_dir, f"b1pwer_playbook_{safe}_{ts}.html")
        self._generate_html(html_path)
        self.results["report_html"] = html_path

        # PDF
        try:
            pdf = PDFReporter(self.output_dir)
            sections = self._build_pdf_sections()
            pdf_path = pdf.generate(
                f"Playbook - {self.results['target']}",
                sections,
                {"Target": self.results["target"], "Duration": f"{self.results['duration']}s",
                 "Modules": f"{len(self.results['modules_run'])} run, {len(self.results['modules_failed'])} failed"}
            )
            self.results["report_pdf"] = pdf_path
        except:
            pass

        # Save to history
        try:
            from .history import HistoryDB
            db = HistoryDB()
            db.save_scan(
                target=self.results["target"],
                ip=self.results.get("ip", ""),
                profile="playbook",
                ports=[f"{p['port']}/{p['service']}" for p in self.results.get("tcp_ports", [])],
                services=[p.get("version", "") for p in self.results.get("tcp_ports", [])],
                vulns=[f"[{v['severity']}] {v['name']}" for v in self.results.get("nuclei", [])],
                web_title=self.results.get("web_info", {}).get("title", ""),
                duration=self.results["duration"]
            )
            db.close()
        except:
            pass

        # Alerts for critical findings
        try:
            from .alert import AlertManager
            am = AlertManager()
            for v in self.results.get("nuclei", []):
                if v["severity"] in ("CRITICAL", "HIGH"):
                    am.alert(v["severity"], v["name"], v.get("cve", ""), self.results["target"])
            for e in self.results.get("exploits", []):
                if e["severity"] == "CRITICAL":
                    am.alert("CRITICAL", f"Known exploit: {e['cve']}", f"Port {e['port']}", self.results["target"])
            self.results["alerts_sent"] = len(self.alerts)
        except:
            pass

    def _generate_html(self, path: str):
        r = self.results
        port_rows = ""
        for p in r.get("tcp_ports", []):
            port_rows += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['version'] or '-'}</td></tr>"

        vuln_rows = ""
        for v in r.get("nuclei", []):
            color = "#ff0000" if v["severity"] in ("CRITICAL", "HIGH") else "#ffcc00"
            vuln_rows += f"<tr><td style='color:{color};font-weight:bold'>{v['severity']}</td><td>{v['cve'] or v['id'][:30]}</td><td>{v['name']}</td></tr>"

        html = f"""<!DOCTYPE html><html><head><title>b1pwer Playbook - {r['target']}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1100px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#161b22,#21262d);padding:30px;border-radius:12px;margin-bottom:20px;border-left:4px solid #58a6ff}}
.header h1{{color:#58a6ff;margin:0}}
.header p{{color:#8b949e;margin:4px 0}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.stat{{background:#161b22;padding:15px;border-radius:8px;text-align:center;border:1px solid #30363d}}
.stat .num{{font-size:2em;color:#58a6ff;font-weight:bold}}
.stat .label{{color:#8b949e;font-size:0.8em;text-transform:uppercase}}
.section{{background:#161b22;padding:20px;border-radius:8px;margin-bottom:15px;border:1px solid #30363d}}
.section h2{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px;margin-top:0}}
table{{width:100%;border-collapse:collapse}}
th{{background:#21262d;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #21262d}}
.footer{{text-align:center;color:#484f58;margin-top:30px;padding:20px}}
</style></head><body><div class="container">
<div class="header">
<h1>b1pwer Playbook Report</h1>
<p>Aaron Paulos Division | b1pwer.surge.sh</p>
<p>Target: {r['target']} ({r.get('ip','')}) | Duration: {r.get('duration',0)}s</p>
</div>
<div class="stats">
<div class="stat"><div class="num">{len(r.get('tcp_ports',[]))}</div><div class="label">TCP Ports</div></div>
<div class="stat"><div class="num">{len(r.get('udp_ports',[]))}</div><div class="label">UDP Ports</div></div>
<div class="stat"><div class="num" style="color:red">{len(r.get('nuclei',[]))}</div><div class="label">Vulns</div></div>
<div class="stat"><div class="num">{len(r.get('exploits',[]))}</div><div class="label">Exploits</div></div>
</div>
<div class="section"><h2>TCP Ports</h2><table><tr><th>Port</th><th>Service</th><th>Version</th></tr>{port_rows}</table></div>
<div class="section"><h2>Vulnerabilities (Nuclei)</h2><table><tr><th>Severity</th><th>ID</th><th>Name</th></tr>{vuln_rows or '<tr><td colspan=3>None</td></tr>'}</table></div>
<div class="section"><h2>Modules</h2><p>Run: {', '.join(r.get('modules_run',[]))}</p><p>Failed: {', '.join(r.get('modules_failed',[])) or 'None'}</p></div>
<div class="footer"><p><b>b1pwer v1.0</b> | Aaron Paulos Division | b1pwer.surge.sh</p></div>
</div></body></html>"""
        with open(path, "w") as f:
            f.write(html)

    def _build_pdf_sections(self) -> list:
        r = self.results
        sections = []

        port_table = "<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>"
        for p in r.get("tcp_ports", []):
            port_table += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['version'] or '-'}</td></tr>"
        port_table += "</table>"
        sections.append({"heading": "TCP Ports", "content": port_table})

        vuln_table = "<table><tr><th>Severity</th><th>ID</th><th>Name</th></tr>"
        for v in r.get("nuclei", []):
            cls = "critical" if v["severity"] in ("CRITICAL", "HIGH") else "medium"
            vuln_table += f"<tr><td class='{cls}'>{v['severity']}</td><td>{v['cve'] or v['id'][:30]}</td><td>{v['name']}</td></tr>"
        vuln_table += "</table>"
        sections.append({"heading": "Vulnerabilities", "content": vuln_table})

        sections.append({
            "heading": "Summary",
            "content": f"<p>Modules run: {len(r.get('modules_run',[]))} | Failed: {len(r.get('modules_failed',[]))} | Duration: {r.get('duration',0)}s</p>"
        })
        return sections

    def _print_summary(self):
        r = self.results
        print(f"\n  {'='*50}")
        print(f"  PLAYBOOK COMPLETE: {r['target']}")
        print(f"  {'='*50}")
        print(f"  Duration:     {r.get('duration', 0)}s")
        print(f"  TCP Ports:    {len(r.get('tcp_ports', []))}")
        print(f"  UDP Ports:    {len(r.get('udp_ports', []))}")
        print(f"  Vulns:        {len(r.get('nuclei', []))}")
        print(f"  Exploits:     {len(r.get('exploits', []))}")
        print(f"  Subdomains:   {len(r.get('subdomains', []))}")
        print(f"  API Endpoints:{len(r.get('api_endpoints', []))}")
        print(f"  Cloud Issues: {len(r.get('cloud', []))}")
        print(f"  Modules:      {len(r.get('modules_run', []))} run, {len(r.get('modules_failed', []))} failed")
        if r.get('modules_failed'):
            print(f"  Failed:       {r['modules_failed']}")
        print(f"\n  Reports:")
        for key in ['report_json', 'report_html', 'report_pdf']:
            if r.get(key):
                print(f"    {key.replace('report_','').upper()}: {r[key]}")
        print(f"  {'='*50}\n")
