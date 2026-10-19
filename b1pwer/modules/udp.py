"""
b1pwer.modules.udp - UDP port scanning
"""
import socket
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class UDPResult:
    port: int
    state: str
    service: str = ""
    version: str = ""


class UDPScanner:
    TOP_UDP_PORTS = [
        53, 67, 68, 69, 123, 137, 138, 161, 500,
        1900, 389, 636, 1901, 5141, 5060, 5061,
        8000, 9100, 10000, 15000, 19000, 3389,
        4444, 5353, 5555, 7000, 8443, 9999,
        10001, 12345, 16111, 20000, 30000, 40000,
        50000, 60000, 65000, 65535
    ]

    def scan(self, target: str, ports: list = None, timeout: float = 0.5,
             threads: int = 40) -> list:
        if ports is None:
            ports = self.TOP_UDP_PORTS[:5]
        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(self._check_port, target, p, timeout): p for p in ports}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        results.sort(key=lambda x: x.port)
        return results

    def _check_port(self, target: str, port: int, timeout: float) -> UDPResult:
        service = self._port_name(port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            sock.close()
            return UDPResult(port=port, state="open", service=service)
        except socket.timeout:
            return UDPResult(port=port, state="open|filtered", service=service)
        except ConnectionRefusedError:
            return UDPResult(port=port, state="closed", service=service)
        except:
            return UDPResult(port=port, state="unknown", service=service)

    def _port_name(self, port: int) -> str:
        try:
            return socket.getservbyport(port, "udp")
        except:
            return ""
