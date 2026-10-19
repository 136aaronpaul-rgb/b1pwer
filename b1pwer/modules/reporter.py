"""
b1pwer.reporter - Multi-format report generation
"""
import json
import os
from datetime import datetime
from .scanner import HostResult


class Reporter:
    def __init__(self, output_dir: str = "./b1pwer_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def _filename(self, target: str, fmt: str) -> str:
        safe = target.replace(".", "_").replace("/", "_").replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"b1pwer_{safe}_{ts}.{fmt}"

    def save_json(self, result: HostResult) -> str:
        filename = self._filename(result.target, "json")
        path = os.path.join(self.output_dir, filename)
        data = {
            "tool": "b1pwer", "version": "1.0.0",
            "author": "Aaron Paulos", "org": "Aaron Paulos Division",
            "website": "b1pwer.surge.sh",
            "scan_time": result.scan_time,
            "duration_sec": round(result.scan_duration, 2),
            "target": result.target, "ip": result.ip,
            "hostname": result.hostname, "os": result.os_guess,
            "geo": result.geo, "org": result.org, "asn": result.asn,
            "ports": [
                {"port": p.port, "proto": p.protocol, "state": p.state,
                 "service": p.service, "version": p.version}
                for p in result.ports
            ],
            "dns": result.dns_records,
            "web": result.web_info,
            "vulnerabilities": result.vulnerabilities
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    def save_html(self, result: HostResult) -> str:
        filename = self._filename(result.target, "html")
        path = os.path.join(self.output_dir, filename)
        port_rows = ""
        for p in result.ports:
            port_rows += f"<tr><td>{p.port}/{p.protocol}</td><td>{p.state}</td><td>{p.service}</td><td>{p.version}</td></tr>"
        vuln_rows = ""
        for v in result.vulnerabilities:
            color = "#ff0000" if v["severity"] == "CRITICAL" else "#ff6600" if v["severity"] == "HIGH" else "#ffcc00"
            vuln_rows += f"<tr><td style='color:{color};font-weight:bold'>{v['severity']}</td><td>{v['script']}</td><td>{v['port']}</td><td>{v['detail'][:200]}</td></tr>"
        dns_rows = ""
        for rtype, records in result.dns_records.items():
            if records:
                dns_rows += f"<tr><td>{rtype}</td><td>{', '.join(records)}</td></tr>"
        header_rows = ""
        for k, v in result.web_info.get("headers", {}).items():
            header_rows += f"<tr><td>{k}</td><td>{v}</td></tr>"
        html = f"""<!DOCTYPE html>
<html><head><title>b1pwer Report - {result.target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1000px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#161b22,#21262d);padding:30px;border-radius:12px;margin-bottom:20px;border-left:4px solid #58a6ff}}
.header h1{{margin:0;color:#58a6ff;font-size:2.2em}}
.header p{{color:#8b949e;margin:4px 0}}
.section{{background:#161b22;padding:20px;border-radius:8px;margin-bottom:15px;border:1px solid #30363d}}
.section h2{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:8px;margin-top:0}}
table{{width:100%;border-collapse:collapse}}
th{{background:#21262d;padding:10px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:10px;border-bottom:1px solid #21262d}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.card{{background:#21262d;padding:12px;border-radius:6px}}
.card .label{{color:#8b949e;font-size:0.8em;text-transform:uppercase}}
.card .value{{color:#fff;font-size:1.1em;margin-top:4px}}
.footer{{text-align:center;color:#484f58;margin-top:30px;padding:20px;border-top:1px solid #30363d}}
</style></head><body><div class="container">
<div class="header">
<h1>⚡ b1pwer v1.0</h1>
<p>Aaron Paulos Division | b1pwer.surge.sh</p>
<p>Scan: {result.scan_time} | Duration: {result.scan_duration:.1f}s</p>
</div>
<div class="section"><h2>🎯 Target</h2>
<div class="grid">
<div class="card"><div class="label">Target</div><div class="value">{result.target}</div></div>
<div class="card"><div class="label">IP</div><div class="value">{result.ip}</div></div>
<div class="card"><div class="label">Hostname</div><div class="value">{result.hostname or 'N/A'}</div></div>
<div class="card"><div class="label">OS</div><div class="value">{result.os_guess or 'N/A'}</div></div>
<div class="card"><div class="label">Location</div><div class="value">{result.geo}</div></div>
<div class="card"><div class="label">Organization</div><div class="value">{result.org}</div></div>
</div></div>
<div class="section"><h2>🔌 Open Ports ({len(result.ports)})</h2>
<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
{port_rows or '<tr><td colspan="4">None found</td></tr>'}</table></div>
<div class="section"><h2>🌐 Web</h2>
<div class="grid">
<div class="card"><div class="label">HTTP</div><div class="value">{'✅' if result.web_info.get('http') else '❌'}</div></div>
<div class="card"><div class="label">HTTPS</div><div class="value">{'✅' if result.web_info.get('https') else '❌'}</div></div>
<div class="card"><div class="label">Server</div><div class="value">{result.web_info.get('server','N/A')}</div></div>
<div class="card"><div class="label">Title</div><div class="value">{result.web_info.get('title','N/A')}</div></div>
</div>
{f'<table style="margin-top:12px"><tr><th>Security Header</th><th>Value</th></tr>{header_rows}</table>' if header_rows else ''}
</div>
<div class="section"><h2>🔒 DNS Records</h2>
<table><tr><th>Type</th><th>Records</th></tr>{dns_rows or '<tr><td colspan="2">None</td></tr>'}</table></div>
<div class="section"><h2>⚠️ Vulnerabilities ({len(result.vulnerabilities)})</h2>
<table><tr><th>Severity</th><th>Script</th><th>Port</th><th>Detail</th></tr>
{vuln_rows or '<tr><td colspan="4">None detected</td></tr>'}</table></div>
<div class="footer">
<p><strong>b1pwer v1.0</strong> | Built by <strong>Aaron Paulos</strong> | Aaron Paulos Division</p>
<p>b1pwer.surge.sh | ⚠️ For authorized security testing only</p>
</div></div></body></html>"""
        with open(path, "w") as f:
            f.write(html)
        return path

    def save_all(self, result: HostResult) -> dict:
        return {"json": self.save_json(result), "html": self.save_html(result)}
