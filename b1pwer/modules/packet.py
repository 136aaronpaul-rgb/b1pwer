"""
b1pwer.modules.packet - Live packet capture and analysis using Scapy
"""
import subprocess
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    ttl: int = 0
    flags: str = ""
    info: str = ""


class PacketSniffer:
    def capture(self, iface: str = None, count: int = 100,
                duration: int = 10, filter_str: str = "") -> list:
        """Capture packets using tcpdump (more reliable than scapy for live capture)."""
        if not iface:
            iface = self._find_iface()

        cmd = f"tcpdump -i {iface} -c {count} -n -q -l"
        if filter_str:
            cmd += f" {filter_str}"
        cmd += " 2>/dev/null"

        packets = []
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=duration
            )
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                p = self._parse_line(line)
                if p:
                    packets.append(p)
        except subprocess.TimeoutExpired:
            pass
        except:
            pass
        return packets

    def _find_iface(self) -> str:
        result = subprocess.run(
            "ip route | grep default | awk '{print $5}'",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        return result if result else "eth0"

    def _parse_line(self, line: str) -> Optional[PacketInfo]:
        import re
        # tcpdump format: IP src > dst: proto, length N
        m = re.match(r'IP (\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): (\w+), length (\d+)', line)
        if m:
            return PacketInfo(
                src_ip=m.group(1),
                dst_ip=m.group(2),
                protocol=m.group(3),
                length=int(m.group(4))
            )
        # TCP/UDP with ports
        m = re.match(r'IP (\d+\.\d+\.\d+\.\d+\.(\d+)) > (\d+\.\d+\.\d+\.\d+\.(\d+)):', line)
        if m:
            return PacketInfo(
                src_ip=m.group(1).rsplit('.', 1)[0],
                dst_ip=m.group(3).rsplit('.', 1)[0],
                protocol="TCP" if "TCP" in line else "UDP",
                src_port=int(m.group(2)),
                dst_port=int(m.group(4))
            )
        return None

    def summarize(self, packets: list) -> dict:
        summary = {
            "total": len(packets),
            "protocols": {},
            "top_talkers": {},
            "top_destinations": {},
            "unique_sources": set(),
            "unique_dests": set()
        }
        for p in packets:
            summary["protocols"][p.protocol] = summary["protocols"].get(p.protocol, 0) + 1
            summary["top_talkers"][p.src_ip] = summary["top_talkers"].get(p.src_ip, 0) + 1
            summary["top_destinations"][p.dst_ip] = summary["top_destinations"].get(p.dst_ip, 0) + 1
            summary["unique_sources"].add(p.src_ip)
            summary["unique_dests"].add(p.dst_ip)

        summary["top_talkers"] = dict(sorted(
            summary["top_talkers"].items(), key=lambda x: x[1], reverse=True
        )[:10])
        summary["top_destinations"] = dict(sorted(
            summary["top_destinations"].items(), key=lambda x: x[1], reverse=True
        )[:10])
        summary["unique_sources"] = list(summary["unique_sources"])
        summary["unique_dests"] = list(summary["unique_dests"])
        return summary
