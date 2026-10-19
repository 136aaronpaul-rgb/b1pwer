"""
b1pwer.modules.iot - IoT device discovery & vulnerability scanner
"""
import socket
import subprocess
import re
from dataclasses import dataclass, field


@dataclass
class IoTDevice:
    ip: str
    device_type: str = "unknown"
    brand: str = ""
    model: str = ""
    firmware: str = ""
    services: list = field(default_factory=list)
    vulns: list = field(default_factory=list)


class IoTScanner:
    IoT_PORTS = {
        80: "web", 8080: "web-alt", 443: "https",
        554: "rtsp", 1900: "upnp", 1883: "mqtt",
        9100: "printer", 3777: "printer", 9101: "printer",
        23: "telnet", 21: "ftp", 22: "ssh",
        8000: "web-iot", 8081: "web-iot", 8443: "https-alt",
        1900: "upnp", 32768: "upnp-alt",
        5353: "mdns", 1900: "upnp",
    }

    def discover(self, subnet: str = None, timeout: int = 10) -> list:
        if not subnet:
            result = subprocess.run(
                "ip route | grep default | awk '{print $3}' | sed 's|/.*||' | sed 's|\\.[0-9]*$|.0/24|'",
                shell=True, capture_output=True, text=True
            ).stdout.strip()
            subnet = result if result else "192.168.1.0/24"

        devices = []
        try:
            out = subprocess.run(
                f"nmap -sn -n {subnet} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            ).stdout
            hosts = re.findall(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", out)
        except:
            hosts = []

        for ip in hosts:
            device = self._probe_device(ip)
            if device:
                devices.append(device)
        return devices

    def _probe_device(self, ip: str) -> IoTDevice | None:
        device = IoTDevice(ip=ip)
        is_iot = False

        for port, service in self.IoT_PORTS.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    device.services.append(f"{port}/{service}")
                    if port in (554, 1900, 1883, 9100, 3777, 8000, 8081, 23):
                        is_iot = True
                    s.close()
            except:
                pass

        # Try to identify device
        try:
            out = subprocess.run(
                f"nmap -Pn -p 80,8080,8000 --script=http-title,http-headers {ip} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r'http_title:\s*"(.*?)"', out)
            if m and m.group(1):
                title = m.group(1).lower()
                device.model = m.group(1)
                if any(k in title for k in ["router", "camera", "printer", "iot", "smart", "hub", "nas", "switch", "ap "]):
                    is_iot = True
                if "dlink" in title: device.brand = "D-Link"
                elif "tp-link" in title or "tplink" in title: device.brand = "TP-Link"
                elif "netgear" in title: device.brand = "Netgear"
                elif "ubiquiti" in title: device.brand = "Ubiquiti"
                elif "hikvision" in title: device.brand = "Hikvision"
                elif "dahua" in title: device.brand = "Dahua"
                elif "synology" in title: device.brand = "Synology"
                elif "qnap" in title: device.brand = "QNAP"
                elif "apple" in title or "airport" in title: device.brand = "Apple"
                elif "xbox" in title: device.brand = "Microsoft"
                elif "roku" in title: device.brand = "Roku"
                elif "nest" in title or "google" in title: device.brand = "Google"
                elif "amazon" in title or "echo" in title: device.brand = "Amazon"
        except:
            pass

        # Check for known IoT vulns
        if is_iot or device.services:
            if "23/telnet" in device.services:
                device.vulns.append("Telnet exposed (unencrypted)")
            if "80/web" in device.services or "8080/web-alt" in device.services:
                device.vulns.append("HTTP (not HTTPS) - credentials in plaintext")
            if "1900/upnp" in device.services:
                device.vulns.append("UPnP exposed (SSRF risk)")

        if not device.services and not is_iot:
            return None
        return device

    def scan_vulns(self, device: IoTDevice) -> list:
        vulns = []
        # Check for default credentials
        default_creds = [
            ("admin", "admin"), ("admin", "password"),
            ("admin", ""), ("root", "root"),
            ("root", ""), ("admin", "1234"),
        ]
        # (Would use hydra for actual brute force)
        if "23/telnet" in device.services:
            vulns.append("Telnet: try default credentials (admin/admin, root/root)")
        if "21/ftp" in device.services:
            vulns.append("FTP: try default credentials")
        return vulns
