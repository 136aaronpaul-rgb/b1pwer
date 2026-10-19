"""
b1pwer.modules.arp - ARP table scanner (local network discovery)
"""
import subprocess
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ARPEntry:
    ip: str
    mac: str
    iface: str = ""
    vendor: str = ""
    hostname: str = ""


class ARPScanner:
    def __init__(self):
        self.iface = self._find_iface()

    def _find_iface(self) -> Optional[str]:
        result = subprocess.run(
            "ip route | grep default | awk '{print $5}'",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        return result if result else "eth0"

    def get_local_subnet(self) -> str:
        try:
            result = subprocess.run(
                f"ip -4 addr show {self.iface} | grep -oP 'inet \\K[\\d./]+'",
                shell=True, capture_output=True, text=True
            ).stdout.strip()
            return result if result else "192.168.1.0/24"
        except:
            return "192.168.1.0/24"

    def scan(self, subnet: str = None, timeout: int = 10) -> list:
        if not subnet:
            subnet = self.get_local_subnet()
        entries = []
        # Use nmap -sn for ARP discovery
        try:
            result = subprocess.run(
                f"nmap -sn -PR -PE -n {subnet} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            for line in result.stdout.split("\n"):
                m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip = m.group(1)
                    mac = self._get_mac(ip)
                    vendor = self._lookup_vendor(mac) if mac else ""
                    hostname = self._reverse_dns(ip)
                    entries.append(ARPEntry(
                        ip=ip, mac=mac or "N/A",
                        iface=self.iface, vendor=vendor, hostname=hostname
                    ))
        except:
            # Fallback: read /proc/net/arp
            entries = self._read_proc_arp()
        return entries

    def _get_mac(self, ip: str) -> str:
        try:
            result = subprocess.run(
                f"arp -n {ip} 2>/dev/null | awk '{{print $3}}'",
                shell=True, capture_output=True, text=True, timeout=3
            ).stdout.strip()
            return result if result else ""
        except:
            return ""

    def _read_proc_arp(self) -> list:
        entries = []
        try:
            with open("/proc/net/arp", "r") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip, mac = parts[0], parts[3]
                        if mac != "00:00:00:00:00:00":
                            entries.append(ARPEntry(
                                ip=ip, mac=mac,
                                iface=self.iface,
                                vendor=self._lookup_vendor(mac),
                                hostname=self._reverse_dns(ip)
                            ))
        except:
            pass
        return entries

    def _lookup_vendor(self, mac: str) -> str:
        if not mac or mac == "N/A":
            return ""
        try:
            result = subprocess.run(
                f"macvendorlookup {mac} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=3
            ).stdout.strip()
            return result if result else ""
        except:
            return ""

    def _reverse_dns(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""
