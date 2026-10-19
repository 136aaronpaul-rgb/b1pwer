"""
b1pwer.modules.container - Docker & Kubernetes security scanner
"""
import subprocess
import json
import socket
from dataclasses import dataclass, field


@dataclass
class ContainerFinding:
    container: str
    issue: str
    severity: str
    detail: str = ""


class ContainerScanner:
    def scan_docker(self, target: str = "127.0.0.1", port: int = 2375) -> list:
        findings = []
        # Check if Docker API is exposed
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target, port))
            s.close()
            findings.append(ContainerFinding(
                container="docker",
                issue="Docker API exposed on port 2375",
                severity="CRITICAL",
                detail="Unauthenticated Docker API = full root access"
            ))
        except:
            pass

        # Check HTTPS Docker API
        try:
            import ssl
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s.connect((target, port + 1))
            s.close()
            findings.append(ContainerFinding(
                container="docker",
                issue="Docker API exposed on port 2376 (HTTPS)",
                severity="HIGH",
                detail="Check if TLS certs are self-signed or weak"
            ))
        except:
            pass

        # Check if docker socket is accessible locally
        try:
            result = subprocess.run(
                "docker ps -a 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                containers = result.stdout.strip().split("\n")[1:]
                for c in containers:
                    parts = c.split()
                    if len(parts) > 2:
                        findings.append(ContainerFinding(
                            container=parts[8] if len(parts) > 8 else parts[0],
                            issue="Container running",
                            severity="INFO",
                            detail=parts[-1] if parts else ""
                        ))
        except:
            pass

        return findings

    def scan_k8s(self, target: str = "127.0.0.1", port: int = 8080) -> list:
        findings = []
        # Check if K8s API is exposed
        for port in [8080, 6443, 10250, 10255]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((target, port))
                s.close()
                sev = "CRITICAL" if port in (8080, 10250) else "HIGH"
                findings.append(ContainerFinding(
                    container="kubernetes",
                    issue=f"K8s API/endpoint exposed on port {port}",
                    severity=sev,
                    detail={
                        8080: "Kubelet API (unauthenticated = node compromise)",
                        6443: "K8s API server",
                        10250: "Kubelet read-only port",
                        10255: "Kubelet health check"
                    }.get(port, "")
                ))
            except:
                pass

        # Check if kubectl is available locally
        try:
            result = subprocess.run(
                "kubectl get pods --all-namespaces 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                pods = result.stdout.strip().split("\n")[1:]
                for p in pods[:20]:
                    parts = p.split()
                    if len(parts) > 1:
                        findings.append(ContainerFinding(
                            container=parts[1],
                            issue=f"Pod in {parts[0]}",
                            severity="INFO",
                            detail=parts[2] if len(parts) > 2 else ""
                        ))
        except:
            pass

        return findings

    def full_scan(self, target: str = "127.0.0.1") -> list:
        findings = []
        findings.extend(self.scan_docker(target))
        findings.extend(self.scan_k8s(target))
        return findings
