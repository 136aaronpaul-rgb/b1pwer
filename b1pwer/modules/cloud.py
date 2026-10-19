"""
b1pwer.modules.cloud - Cloud storage & misconfiguration scanner
"""
import subprocess
import socket
import re
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class CloudFinding:
    provider: str
    resource: str
    issue: str
    severity: str
    detail: str = ""


class CloudScanner:
    def scan_s3(self, bucket_name: str) -> list:
        """Check if an S3 bucket is publicly accessible."""
        findings = []
        # Check bucket listing
        try:
            result = subprocess.run(
                f"curl -s --max-time 2 https://{bucket_name}.s3.amazonaws.com/",
                shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "ListBucketResult" in result.stdout:
                findings.append(CloudFinding(
                    provider="AWS S3",
                    resource=bucket_name,
                    issue="Public bucket listing enabled",
                    severity="HIGH",
                    detail="Bucket contents are publicly enumerable"
                ))
            elif "AccessDenied" in result.stdout:
                pass  # Good - access denied
        except:
            pass

        # Check common files
        common_files = [
            "index.html", "robots.txt", ".env", "config.json",
            "wp-config.php", "database.yml", "id_rsa", "credentials.json"
        ]
        for f in common_files:
            try:
                result = subprocess.run(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 "
                    f"https://{bucket_name}.s3.amazonaws.com/{f}",
                    shell=True, capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip() == "200":
                    sev = "CRITICAL" if f in [".env", "id_rsa", "credentials.json", "wp-config.php"] else "MEDIUM"
                    findings.append(CloudFinding(
                        provider="AWS S3",
                        resource=f"{bucket_name}/{f}",
                        issue=f"File publicly accessible: {f}",
                        severity=sev
                    ))
            except:
                pass
        return findings

    def scan_azure(self, container_name: str) -> list:
        """Check Azure blob storage."""
        findings = []
        for storage in [f"{container_name}.blob.core.windows.net"]:
            try:
                result = subprocess.run(
                    f"curl -s --max-time 2 https://{storage}/?restype=container&comp=list",
                    shell=True, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and "Blobs" in result.stdout:
                    findings.append(CloudFinding(
                        provider="Azure Blob",
                        resource=container_name,
                        issue="Container listing publicly accessible",
                        severity="HIGH"
                    ))
            except:
                pass
        return findings

    def scan_gcs(self, bucket_name: str) -> list:
        """Check Google Cloud Storage."""
        findings = []
        try:
            result = subprocess.run(
                f"curl -s --max-time 2 https://storage.googleapis.com/{bucket_name}/",
                shell=True, capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "<Items>" in result.stdout:
                findings.append(CloudFinding(
                    provider="GCS",
                    resource=bucket_name,
                    issue="Bucket listing publicly accessible",
                    severity="HIGH"
                ))
        except:
            pass
        return findings

    def scan_domain(self, domain: str) -> list:
        """Scan for exposed cloud resources related to a domain."""
        findings = []
        # Check for common S3 bucket naming patterns
        base = domain.split(".")[0]
        s3_names = [
            base, f"{base}-data", f"{base}-backup", f"{base}-assets",
            f"{base}-static", f"{base}-media", f"{base}-uploads",
            f"{base}-files", f"{base}-public", f"{base}-cdn"
        ]
        for name in s3_names:
            f = self.scan_s3(name)
            findings.extend(f)
        return findings

    def full_scan(self, domain: str) -> list:
        """Full cloud scan for a domain."""
        findings = []
        findings.extend(self.scan_domain(domain))
        return findings
