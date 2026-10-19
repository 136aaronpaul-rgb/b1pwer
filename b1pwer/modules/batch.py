"""
b1pwer.modules.batch - Multi-target batch scanning
"""
import subprocess
import time
import json
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class BatchResult:
    target: str
    ip: str = ""
    open_ports: list = field(default_factory=list)
    services: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    web_title: str = ""
    scan_time: str = ""
    duration: float = 0.0
    status: str = "pending"


class BatchScanner:
    def __init__(self, max_threads: int = 5):
        self.max_threads = max_threads
        from .scanner import B1pwerScanner
        self.scanner = B1pwerScanner()

    def load_targets(self, source: str) -> list:
        """Load targets from file, CIDR, or comma-separated string."""
        targets = []
        if os.path.isfile(source):
            with open(source, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        elif "/" in source:
            targets = [source]
        else:
            targets = [t.strip() for t in source.split(",") if t.strip()]
        return targets

    def scan_target(self, target: str, profile: str = "quick") -> BatchResult:
        result = BatchResult(target=target, status="scanning")
        start = time.time()
        try:
            r = self.scanner.scan(target, profile)
            result.ip = r.ip
            result.open_ports = [f"{p.port}/{p.protocol}" for p in r.ports]
            result.services = [f"{p.service} {p.version}".strip() for p in r.ports]
            result.vulns = [f"[{v['severity']}] {v['script']}:{v['port']}" for v in r.vulnerabilities]
            result.web_title = r.web_info.get("title", "")
            result.duration = time.time() - start
            result.status = "done"
        except Exception as e:
            result.status = f"error: {e}"
            result.duration = time.time() - start
        result.scan_time = datetime.now().isoformat()
        return result

    def scan_batch(self, targets: list, profile: str = "quick",
                   threads: int = 5) -> list:
        """Scan multiple targets concurrently."""
        results = []
        print(f"\n  Scanning {len(targets)} target(s) with {threads} threads...")
        print(f"  Profile: {profile}\n")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self.scan_target, t, profile): t
                for t in targets
            }
            done = 0
            for future in as_completed(futures):
                target = futures[future]
                done += 1
                try:
                    result = future.result()
                    results.append(result)
                    ports = len(result.open_ports)
                    vulns = len(result.vulns)
                    status_icon = "✓" if result.status == "done" else "✗"
                    color = "green" if vulns == 0 else "red"
                    print(f"  [{done}/{len(targets)}] {status_icon} {target} → {ports} ports, {vulns} vulns ({result.duration:.1f}s)")
                except Exception as e:
                    print(f"  [{done}/{len(targets)}] ✗ {target} → ERROR: {e}")

        results.sort(key=lambda x: x.target)
        return results

    def save_report(self, results: list, output_dir: str = "./b1pwer_reports") -> str:
        """Save batch results as combined HTML + JSON."""
        os.makedirs(output_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(output_dir, f"b1pwer_batch_{ts}.json")
        html_path = os.path.join(output_dir, f"b1pwer_batch_{ts}.html")

        # JSON
        data = {
            "tool": "b1pwer",
            "type": "batch",
            "timestamp": datetime.now().isoformat(),
            "targets_scanned": len(results),
            "total_open_ports": sum(len(r.open_ports) for r in results),
            "total_vulns": sum(len(r.vulns) for r in results),
            "results": [
                {
                    "target": r.target, "ip": r.ip,
                    "open_ports": r.open_ports, "services": r.services,
                    "vulns": r.vulns, "web_title": r.web_title,
                    "status": r.status, "duration": round(r.duration, 2)
                } for r in results
            ]
        }
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        # HTML
        rows = ""
        for r in results:
            vuln_color = "red" if r.vulns else "green"
            rows += f"""<tr>
            <td>{r.target}</td><td>{r.ip}</td>
            <td>{', '.join(r.open_ports[:5])}{'...' if len(r.open_ports)>5 else ''}</td>
            <td>{r.web_title or '-'}</td>
            <td style="color:{vuln_color};font-weight:bold">{len(r.vulns)}</td>
            <td>{r.duration:.1f}s</td>
            </tr>"""
            for v in r.vulns:
                rows += f"<tr><td colspan='4' style='padding-left:30px;color:red'>⚠ {v}</td><td></td><td></td></tr>"

        html = f"""<!DOCTYPE html><html><head><title>b1pwer Batch Report</title>
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
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;padding:12px;text-align:left;border-bottom:2px solid #30363d}}
td{{padding:10px;border-bottom:1px solid #21262d}}
.footer{{text-align:center;color:#484f58;margin-top:30px;padding:20px}}
</style></head><body><div class="container">
<div class="header">
<h1>b1pwer Batch Report</h1>
<p>Aaron Paulos Division | b1pwer.surge.sh</p>
<p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="stats">
<div class="stat"><div class="num">{len(results)}</div><div class="label">Targets</div></div>
<div class="stat"><div class="num">{sum(len(r.open_ports) for r in results)}</div><div class="label">Open Ports</div></div>
<div class="stat"><div class="num" style="color:red">{sum(len(r.vulns) for r in results)}</div><div class="label">Vulns</div></div>
<div class="stat"><div class="num">{sum(r.duration for r in results):.0f}s</div><div class="label">Total Time</div></div>
</div>
<table>
<tr><th>Target</th><th>IP</th><th>Open Ports</th><th>Web Title</th><th>Vulns</th><th>Time</th></tr>
{rows}
</table>
<div class="footer">
<p><b>b1pwer v1.0</b> | Aaron Paulos Division | b1pwer.surge.sh</p>
</div></div></body></html>"""
        with open(html_path, "w") as f:
            f.write(html)

        return html_path
