"""
b1pwer.modules.ssl - SSL/TLS certificate and cipher audit
"""
import ssl
import socket
from datetime import datetime
from dataclasses import dataclass, field

@dataclass
class SSLScore:
    hostname: str
    port: int = 443
    cert_valid: bool = False
    cert_expiry: str = ""
    days_remaining: int = 0
    issuer: str = ""
    subject: str = ""
    protocol: str = ""
    key_size: int = 0
    score: int = 0

class SSLScanner:
    def audit(self, hostname: str, port: int = 443) -> SSLScore:
        score = SSLScore(hostname=hostname, port=port)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    score.protocol = ssock.version()
                    score.key_size = cert.get("keySize", 0)
                    score.issuer = dict(x[0] for x in cert.get("issuer", [])).get("commonName", "N/A")
                    score.subject = dict(x[0] for x in cert.get("subject", [])).get("commonName", "N/A")
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        score.cert_expiry = expiry_str
                        score.days_remaining = (expiry - datetime.now()).days
                        score.cert_valid = score.days_remaining > 0
            score.score = self._calculate_score(score)
        except ssl.SSLCertVerificationError:
            score.cert_valid = False
            score.score = 20
        except Exception:
            score.score = 0
        return score

    def _calculate_score(self, s: SSLScore) -> int:
        score = 100
        if not s.cert_valid:
            score -= 40
        if s.days_remaining < 7:
            score -= 30
        elif s.days_remaining < 30:
            score -= 15
        if s.protocol and "TLSv1.0" in s.protocol:
            score -= 40
        elif s.protocol and "TLSv1.1" in s.protocol:
            score -= 20
        if s.key_size < 2048:
            score -= 20
        return max(0, score)
