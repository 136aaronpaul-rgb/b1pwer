"""
b1pwer.modules.dashboard - Web dashboard (Flask)
Run: b1pwer --dashboard
Access: http://localhost:9090
"""
import json
import os
import threading
from datetime import datetime


def start_dashboard(port: int = 9090):
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        print("  Flask not installed. Run: pip install flask")
        return

    app = Flask(__name__)
    from .scanner import B1pwerScanner
    from .history import HistoryDB
    from .cve import CVELookup

    @app.route("/")
    def index():
        return """<!DOCTYPE html>
<html><head><title>b1pwer Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:20px}
h1{color:#58a6ff}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin:10px 0}
input,select,button{padding:10px;border-radius:4px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;margin:5px}
button{background:#238636;color:white;cursor:pointer}
button:hover{background:#2ea043}
pre{background:#0d1117;padding:15px;border-radius:6px;overflow-x:auto;font-size:12px}
</style></head><body>
<h1>b1pwer Dashboard</h1>
<p style="color:#8b949e">Aaron Paulos Division | b1pwer.surge.sh</p>
<div class="card">
<h3>Quick Scan</h3>
<input type="text" id="target" placeholder="Target (IP or domain)" style="width:300px">
<select id="profile">
<option value="quick">Quick</option>
<option value="standard">Standard</option>
<option value="full">Full</option>
</select>
<button onclick="doScan()">Scan</button>
<pre id="result">Waiting for scan...</pre>
</div>
<div class="card">
<h3>History</h3>
<button onclick="loadHistory()">Load</button>
<pre id="history">Click Load...</pre>
</div>
<script>
async function doScan(){
  const t=document.getElementById('target').value;
  const p=document.getElementById('profile').value;
  document.getElementById('result').textContent='Scanning '+t+'...';
  const r=await fetch('/api/scan?target='+encodeURIComponent(t)+'&profile='+p);
  const d=await r.json();
  document.getElementById('result').textContent=JSON.stringify(d,null,2);
}
async function loadHistory(){
  const r=await fetch('/api/history');
  const d=await r.json();
  document.getElementById('history').textContent=JSON.stringify(d,null,2);
}
</script>
</body></html>"""

    @app.route("/api/scan")
    def api_scan():
        target = request.args.get("target", "")
        profile = request.args.get("profile", "quick")
        if not target:
            return jsonify({"error": "target required"}), 400
        try:
            scanner = B1pwerScanner()
            result = scanner.scan(target, profile)
            return jsonify({
                "target": result.target,
                "ip": result.ip,
                "ports": [{"port": p.port, "service": p.service, "version": p.version} for p in result.ports],
                "vulns": result.vulnerabilities,
                "duration": round(result.scan_duration, 2)
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/history")
    def api_history():
        db = HistoryDB()
        h = db.get_history(limit=50)
        db.close()
        return jsonify(h)

    @app.route("/api/cve")
    def api_cve():
        cve_id = request.args.get("cve", "")
        if not cve_id:
            return jsonify({"error": "cve required"}), 400
        cl = CVELookup()
        info = cl.lookup(cve_id.upper())
        if info:
            return jsonify({"id": info.cve_id, "score": info.cvss_score, "severity": info.severity, "desc": info.description})
        return jsonify({"error": "not found"}), 404

    print(f"\n  b1pwer Dashboard: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")
    try:
        app.run(host="0.0.0.0", port=port, debug=False)
    except KeyboardInterrupt:
        pass
