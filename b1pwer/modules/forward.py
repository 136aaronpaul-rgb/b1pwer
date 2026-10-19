"""
b1pwer.modules.forward - Port forwarding (proxy chaining)
"""
import subprocess
import socket
import threading
import time
from dataclasses import dataclass


@dataclass
class ForwardRule:
    local_port: int
    remote_host: str
    remote_port: int
    type: str = "tcp"
    active: bool = False


class PortForwarder:
    def __init__(self):
        self.rules = []
        self.threads = []

    def add(self, local_port: int, remote_host: str,
            remote_port: int, ftype: str = "tcp") -> ForwardRule:
        rule = ForwardRule(local_port, remote_host, remote_port, ftype)
        self.rules.append(rule)
        return rule

    def start(self, rule: ForwardRule):
        if rule.type == "tcp":
            t = threading.Thread(target=self._tcp_forward, args=(rule,), daemon=True)
            t.start()
            self.threads.append(t)
            rule.active = True

    def _tcp_forward(self, rule: ForwardRule):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", rule.local_port))
            server.listen(5)
        except:
            rule.active = False
            return
        while rule.active:
            try:
                server.settimeout(1.0)
                client, addr = server.accept()
                threading.Thread(
                    target=self._relay, args=(client, rule), daemon=True
                ).start()
            except socket.timeout:
                continue
            except:
                break
        server.close()

    def _relay(self, client: socket.socket, rule: ForwardRule):
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(5)
            remote.connect((rule.remote_host, rule.remote_port))
            while True:
                try:
                    data = client.recv(4096)
                    if not data:
                        break
                    remote.sendall(data)
                    data = remote.recv(4096)
                    if not data:
                        break
                    client.sendall(data)
                except:
                    break
            client.close()
            remote.close()
        except:
            pass

    def stop(self, rule: ForwardRule):
        rule.active = False

    def stop_all(self):
        for r in self.rules:
            r.active = False

    def list(self) -> list:
        return [
            {"local": f"127.0.0.1:{r.local_port}",
             "remote": f"{r.remote_host}:{r.remote_port}",
             "type": r.type, "active": r.active}
            for r in self.rules
        ]
