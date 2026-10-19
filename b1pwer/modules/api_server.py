"""
b1pwer.modules.api_server - REST API for programmatic access
Run: b1pwer --api-server
Access: http://localhost:8443/api/scan?target=8.8.8.8
"""
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


class B1pwerAPIHandler(BaseHTTPRequestHandler):
    scanner = None
    reporter = None

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/api/scan":
            self._handle_scan(params)
        elif parsed.path == "/api/history":
            self._handle_history(params)
        elif parsed.path == "/api/status":
            self._respond({"status": "ok", "version": "1.0.0"})
        elif parsed.path == "/api/modules":
            self._respond({"modules": [
                "scan", "nuclei", "subs", "ssl", "wifi", "audit",
                "batch", "history", "cve", "exploits", "udp", "arp",
                "topology", "zone", "banner", "rdns", "sniff", "msf",
                "cloud", "api", "playbook", "brute", "smb"
            ]})
        else:
            self._respond({"error": "Not found"}, 404)

    def _handle_scan(self, params):
        target = params.get("target", [""])[0]
        profile = params.get("profile", ["quick"])[0]
        if not target:
            self._respond({"error": "target required"}, 400)
            return
        try:
            from .scanner import B1pwerScanner
            scanner = B1pwerScanner()
            result = scanner.scan(target, profile)
            self._respond({
                "target": result.target,
                "ip": result.ip,
                "ports": [
                    {"port": p.port, "service": p.service, "version": p.version}
                    for p in result.ports
                ],
                "vulns": result.vulnerabilities,
                "duration": result.scan_duration
            })
        except Exception as e:
            self._respond({"error": str(e)}, 500)

    def _handle_history(self, params):
        try:
            from .history import HistoryDB
            db = HistoryDB()
            limit = int(params.get("limit", ["20"])[0])
            self._respond({"history": db.get_history(limit=limit)})
            db.close()
        except Exception as e:
            self._respond({"error": str(e)}, 500)

    def _respond(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def log_message(self, format, *args):
        pass  # Suppress logs


def start_api_server(port: int = 8443):
    server = HTTPServer(("0.0.0.0", port), B1pwerAPIHandler)
    print(f"\n  b1pwer API server running on http://localhost:{port}")
    print(f"  Endpoints:")
    print(f"    GET /api/scan?target=8.8.8.8&profile=quick")
    print(f"    GET /api/history?limit=20")
    print(f"    GET /api/status")
    print(f"    GET /api/modules")
    print(f"\n  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
