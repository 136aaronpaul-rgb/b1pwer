"""
b1pwer.modules.topology - Network topology mapping
"""
import subprocess
import re
import socket
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Node:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    services: list = field(default_factory=list)
    os_guess: str = ""
    is_gateway: bool = False


@dataclass
class TopologyResult:
    subnet: str
    iface: str
    gateway: str = ""
    nodes: list = field(default_factory=list)
    summary: str = ""


class TopologyMapper:
    def __init__(self):
        self.iface = self._find_iface()
        self.subnet = self._find_subnet()
        self.gateway = self._find_gateway()

    def _find_iface(self) -> str:
        result = subprocess.run(
            "ip route | grep default | awk '{print $5}'",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        return result if result else "eth0"

    def _find_subnet(self) -> str:
        try:
            result = subprocess.run(
                f"ip -4 addr show {self.iface} | grep -oP 'inet \\K[\\d./]+'",
                shell=True, capture_output=True, text=True
            ).stdout.strip()
            return result if result else "192.168.1.0/24"
        except:
            return "192.168.1.0/24"

    def _find_gateway(self) -> str:
        try:
            result = subprocess.run(
                "ip route | grep default | awk '{print $3}'",
                shell=True, capture_output=True, text=True
            ).stdout.strip()
            return result if result else ""
        except:
            return ""

    def map(self, timeout: int = 15) -> TopologyResult:
        result = TopologyResult(
            subnet=self.subnet,
            iface=self.iface,
            gateway=self.gateway
        )
        # Discover hosts
        try:
            out = subprocess.run(
                f"nmap -sn -PR -PE -n {self.subnet} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            ).stdout
            hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", out)
        except:
            hosts = []

        for ip in hosts:
            node = Node(ip=ip, is_gateway=(ip == self.gateway))
            # Get MAC
            try:
                mac_out = subprocess.run(
                    f"arp -n {ip} 2>/dev/null | awk '{{print $3}}'",
                    shell=True, capture_output=True, text=True, timeout=3
                ).stdout.strip()
                node.mac = mac_out if mac_out else ""
            except:
                pass
            # Reverse DNS
            try:
                node.hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            # Quick port check (top 5)
            for port in [22, 80, 443, 3389, 8080]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        node.services.append(f"{port}/{socket.getservbyport(port)}")
                    s.close()
                except:
                    pass
            result.nodes.append(node)

        # Summary
        svc_count = sum(len(n.services) for n in result.nodes)
        result.summary = (
            f"{len(result.nodes)} hosts on {self.subnet} | "
            f"Gateway: {self.gateway} | "
            f"{svc_count} services detected"
        )
        return result

    def to_ascii(self, result: TopologyResult) -> str:
        lines = []
        lines.append(f"  Network: {result.subnet} ({result.iface})")
        lines.append(f"  Gateway: {result.gateway}")
        lines.append(f"  Hosts:   {len(result.nodes)}")
        lines.append("")
        lines.append(f"  {'IP':<16} {'MAC':<18} {'Hostname':<16} {'Services'}")
        lines.append(f"  {'-'*16} {'-'*18} {'-'*16} {'-'*20}")
        for n in result.nodes:
            gw = " [GW]" if n.is_gateway else ""
            svcs = ", ".join(n.services[:3]) + ("..." if len(n.services) > 3 else "")
            lines.append(f"  {n.ip:<16} {n.mac:<18} {n.hostname:<16} {svcs}{gw}")
        return "\n".join(lines)
