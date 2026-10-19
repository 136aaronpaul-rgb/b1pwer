"""
b1pwer.modules.banner - Service banner grabbing
"""
import socket
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class BannerResult:
    port: int
    service: str
    banner: str
    version: str = ""
    os_hint: str = ""


class BannerGrabber:
    PROTOCOLS = {
        21: ("FTP", b"USER b1pwer\r\nQUIT\r\n"),
        22: ("SSH", b""),
        25: ("SMTP", b"QUIT\r\n"),
        53: ("DNS", b""),
        80: ("HTTP", b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"),
        110: ("POP3", b"QUIT\r\n"),
        143: ("IMAP", b"QUIT\r\n"),
        389: ("LDAP", b""),
        443: ("HTTPS", b""),
        636: ("LDAPS", b""),
        993: ("IMAPS", b""),
        995: ("POPS", b""),
        1433: ("MSSQL", b"\x0b\x00\x00\x01\x00\x00\x00\x00"),
        1521: ("Oracle", b""),
        3306: ("MySQL", b"\x00\x00\x00\x00\x0a"),
        3389: ("RDP", b""),
        5432: ("PostgreSQL", b"\x00\x00\x00\x04\x04\xd2\x16\x2f"),
        5900: ("VNC", b""),
        6379: ("Redis", b"INFO\r\n"),
        8080: ("HTTP-ALT", b"GET / HTTP/1.0\r\nHost: x\r\n\r\n"),
        8443: ("HTTPS-ALT", b""),
        27017: ("MongoDB", b"\x16\x00\x00\x00\x00\x00\x00\x00"),
        9200: ("Elasticsearch", b"GET /\r\n"),
    }

    def grab(self, target: str, ports: list = None, timeout: float = 1.0,
             threads: int = 20) -> list:
        if ports is None:
            ports = list(self.PROTOCOLS.keys())
        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._grab_one, target, p, timeout): p
                for p in ports
            }
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r:
                        results.append(r)
                except:
                    pass
        results.sort(key=lambda x: x.port)
        return results

    def _grab_one(self, target: str, port: int, timeout: float) -> BannerResult | None:
        proto_name, payload = self.PROTOCOLS.get(port, (None, b""))
        if proto_name is None:
            return None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            banner = ""
            if payload:
                sock.send(payload)
                time.sleep(0.3)
            banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()
            sock.close()

            if not banner:
                return None

            version = self._extract_version(banner, proto_name)
            return BannerResult(
                port=port,
                service=proto_name,
                banner=banner[:500],
                version=version,
                os_hint=self._guess_os(banner)
            )
        except:
            return None

    def _extract_version(self, banner: str, service: str) -> str:
        import re
        patterns = {
            "SSH": r'(\d+\.\d+[\.\d]*)',
            "FTP": r'(\d+\.\d+[\.\d]*)',
            "SMTP": r'(\d+\.\d+[\.\d]*)',
            "HTTP": r'Server:\s*(.+)',
            "MySQL": r'(\d+\.\d+[\.\d]*)',
            "PostgreSQL": r'(\d+\.\d+[\.\d]*)',
            "Redis": r'redis_version:(\d+\.\d+[\.\d]*)',
            "MongoDB": r'version:(\d+\.\d+[\.\d]*)',
            "Elasticsearch": r'verSION\":"(\d+\.\d+[\.\d]*)',
        }
        pat = patterns.get(service, r'(\d+\.\d+[\.\d]*)')
        m = re.search(pat, banner)
        return m.group(1) if m else ""

    def _guess_os(self, banner: str) -> str:
        b = banner.lower()
        if "windows" in b or "microsoft" in b:
            return "Windows"
        if "linux" in b or "ubuntu" in b or "debian" in b:
            return "Linux"
        if "freebsd" in b:
            return "FreeBSD"
        if "openbsd" in b:
            return "OpenBSD"
        if "cisco" in b:
            return "Cisco IOS"
        return ""
