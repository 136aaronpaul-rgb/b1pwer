"""
b1pwer.modules.proxy - Reverse proxy & CDN detection
"""
import subprocess
import re
import socket
from dataclasses import dataclass, field


@dataclass
class ProxyResult:
    target: str
    proxy_type: str = "none"
    provider: str = ""
    origin_ip: str = ""
    headers: dict = field(default_factory=dict)
    notes: str = ""


class ProxyDetector:
    SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "server: cloudflare", "cf-"],
            "provider": "Cloudflare"
        },
        "akamai": {
            "headers": ["x-akamai-transformed", "server: akamai", "x-akamai"],
            "provider": "Akamai"
        },
        "fastly": {
            "headers": ["x-served-by: cache", "fastly", "x-timer"],
            "provider": "Fastly"
        },
        "incapsula": {
            "headers": ["x-iinfo", "server: incapsula", "visid_incap"],
            "provider": "Imperva/Incapsula"
        },
        "aws": {
            "headers": ["x-amz-cf-id", "server: aws", "x-cache: aws"],
            "provider": "AWS CloudFront"
        },
        "google": {
            "headers": ["x-google-trace-id", "server: gws", "via: google"],
            "provider": "Google Cloud CDN"
        },
        "nginx": {
            "headers": ["server: nginx"],
            "provider": "Nginx"
        },
        "apache": {
            "headers": ["server: apache"],
            "provider": "Apache"
        },
        "iis": {
            "headers": ["server: microsoft-iis", "x-aspnet"],
            "provider": "IIS"
        },
    }

    def detect(self, target: str) -> ProxyResult:
        result = ProxyResult(target=target)

        # Get headers
        for scheme in ["https", "http"]:
            try:
                out = subprocess.run(
                    f"curl -skI --max-time 5 {scheme}://{target} 2>/dev/null",
                    shell=True, capture_output=True, text=True, timeout=10
                ).stdout
                if out:
                    for line in out.split("\n"):
                        if ":" in line:
                            key, val = line.split(":", 1)
                            result.headers[key.strip().lower()] = val.strip()
                    break
            except:
                continue

        # Detect proxy
        headers_str = " ".join(result.headers.values()).lower()
        for proxy_name, sig in self.SIGNATURES.items():
            if any(h in headers_str for h in sig["headers"]):
                result.proxy_type = proxy_name
                result.provider = sig["provider"]
                break

        # Try to find origin IP
        if result.proxy_type in ("cloudflare", "akamai", "fastly", "incapsula", "aws", "google"):
            result.origin_ip = self._find_origin(target)
            result.notes = f"Behind {result.provider} - origin IP may be different"

        return result

    def _find_origin(self, domain: str) -> str:
        """Try to find origin IP via DNS history or direct lookup."""
        # Check if there's a non-CDN IP
        try:
            out = subprocess.run(
                f"dig +short A {domain} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout.strip()
            ips = [l.strip() for l in out.split("\n") if l.strip()]
            # Cloudflare IPs are in 104.16.0.0/13, 172.64.0.0/13, etc.
            for ip in ips:
                if not any(ip.startswith(prefix) for prefix in
                           ["104.16.", "104.17.", "172.64.", "172.65.",
                            "131.0.72.", "184.105.", "146.66.", "188.114."]):
                    return ip
        except:
            pass
        return ""
