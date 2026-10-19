"""
b1pwer.modules.reverse - Bulk reverse DNS lookup
"""
import socket
import subprocess
import ipaddress
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class ReverseRecord:
    ip: str
    hostname: str = ""
    forward_ip: str = ""
    verified: bool = False


class ReverseDNS:
    def lookup(self, ip: str) -> ReverseRecord:
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass
        # Verify forward resolution
        forward_ip = ""
        verified = False
        if hostname:
            try:
                forward_ip = socket.gethostbyname(hostname)
                verified = (forward_ip == ip)
            except:
                pass
        return ReverseRecord(ip=ip, hostname=hostname, forward_ip=forward_ip, verified=verified)

    def lookup_range(self, subnet: str) -> list:
        """Reverse DNS for all IPs in a subnet (max /24)."""
        network = ipaddress.ip_network(subnet, strict=False)
        if network.num_addresses > 256:
            subnet = str(ipaddress.ip_network(f"{network.network_address}/24", strict=False))
            network = ipaddress.ip_network(subnet, strict=False)

        ips = [str(ip) for ip in network.hosts()]
        results = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(self.lookup, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r.hostname:
                        results.append(r)
                except:
                    pass
        results.sort(key=lambda x: ipaddress.ip_address(x.ip))
        return results

    def lookup_list(self, ips: list) -> list:
        """Reverse DNS for a list of IPs."""
        results = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(self.lookup, ip): ip for ip in ips}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        return results
