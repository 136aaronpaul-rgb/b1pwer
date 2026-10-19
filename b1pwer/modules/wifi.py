"""
b1pwer.modules.wifi - WiFi network scanner
"""
import subprocess
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class WiFiNetwork:
    bssid: str
    ssid: str
    channel: int
    frequency: str
    signal: int
    encryption: str
    vendor: str = ""


class WiFiScanner:
    def __init__(self):
        self.wlan = self._find_wifi()

    def _find_wifi(self) -> Optional[str]:
        for iface in ["wlan0", "wlan1", "mon0"]:
            if subprocess.run(
                f"ip link show {iface} > /dev/null 2>&1", shell=True
            ).returncode == 0:
                return iface
        result = subprocess.run(
            "ip link show | grep -oP 'wlan\\d+'", shell=True,
            capture_output=True, text=True
        ).stdout.strip()
        return result.split("\n")[0] if result else None

    def scan(self, timeout: int = 10) -> list:
        if not self.wlan:
            return []
        try:
            result = subprocess.run(
                f"iwlist {self.wlan} scan 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=timeout
            )
            networks = []
            seen = set()
            current = {}

            for line in result.stdout.split("\n"):
                if "Cell" in line:
                    if current.get("bssid") and current["bssid"] not in seen:
                        networks.append(self._parse(current))
                        seen.add(current["bssid"])
                    current = {}
                m = re.search(r"Address:\s+([\w:]+)", line)
                if m:
                    current["bssid"] = m.group(1)
                m = re.search(r"ESSID:\s+(.*)", line)
                if m:
                    current["ssid"] = m.group(1).strip()
                m = re.search(r"Channel:\s+(\d+)", line)
                if m:
                    current["channel"] = int(m.group(1))
                m = re.search(r"signal:\s+(-?\d+)", line)
                if m:
                    current["signal"] = int(m.group(1))
                m = re.search(r"Encryption key:\s+(on|off)", line)
                if m:
                    current["encryption"] = m.group(1)
                m = re.search(r"Quality:\s+(\d+)/(\d+)", line)
                if m:
                    current["quality"] = int(m.group(1))

            if current.get("bssid") and current["bssid"] not in seen:
                networks.append(self._parse(current))

            networks.sort(key=lambda x: x.signal, reverse=True)
            return networks
        except Exception:
            return []

    def _parse(self, data: dict) -> WiFiNetwork:
        channel = data.get("channel", 0)
        freq = f"{channel} GHz" if channel > 14 else f"{2400 + (channel * 5)} MHz"
        enc = "Open" if data.get("encryption") == "off" else "Encrypted"
        return WiFiNetwork(
            bssid=data.get("bssid", "N/A"),
            ssid=data.get("ssid", "<hidden>"),
            channel=channel,
            frequency=freq,
            signal=data.get("signal", 0),
            encryption=enc,
            vendor=self._lookup_vendor(data.get("bssid", ""))
        )

    def _lookup_vendor(self, bssid: str) -> str:
        try:
            result = subprocess.run(
                f"macvendorlookup {bssid} 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            ).stdout.strip()
            return result if result else ""
        except:
            return ""
