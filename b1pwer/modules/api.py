"""
b1pwer.modules.api - Hidden API endpoint discovery
"""
import subprocess
import socket
import re
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class APIEndpoint:
    path: str
    method: str
    status: int
    content_type: str = ""
    size: int = 0
    interesting: bool = False
    reason: str = ""


class APIDiscoverer:
    COMMON_PATHS = [
        "/", "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/auth", "/api/login", "/api/register",
        "/api/admin", "/api/config", "/api/debug", "/api/health",
        "/api/status", "/api/metrics", "/api/internal",
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        "/graphql", "/graphiql", "/playground",
        "/.env", "/.git/config", "/.git/HEAD",
        "/wp-admin", "/wp-login.php", "/xmlrpc.php",
        "/phpmyadmin", "/admin", "/console", "/manager/html",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/actuator/configprops", "/actuator/mappings",
        "/debug", "/trace", "/server-status",
        "/backup", "/db", "/dump", "/sql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/security.txt",
        "/api/swagger", "/v2/api-docs", "/v3/api-docs",
        "/internal", "/private", "/secret", "/hidden",
        "/test", "/dev", "/staging", "/old",
        "/upload", "/uploads", "/files", "/media",
        "/download", "/export", "/import",
        "/webhook", "/webhooks", "/callback", "/notify",
        "/token", "/oauth", "/oauth2", "/saml", "/sso",
        "/session", "/sessions", "/user", "/users",
        "/profile", "/account", "/settings", "/preferences",
        "/search", "/query", "/data", "/report",
    ]

    def scan(self, target: str, scheme: str = "https",
             timeout: float = 1.5, threads: int = 30) -> list:
        """Scan for hidden API endpoints."""
        if not target.startswith("http"):
            target = f"{scheme}://{target}"
        target = target.rstrip("/")

        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._check_path, target, p, timeout): p
                for p in self.COMMON_PATHS
            }
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r and r.status != 404:
                        results.append(r)
                except:
                    pass

        results.sort(key=lambda x: (not x.interesting, x.status, x.path))
        return results

    def _check_path(self, base: str, path: str, timeout: float) -> APIEndpoint | None:
        url = f"{base}{path}"
        try:
            result = subprocess.run(
                f"curl -sk -o /dev/null -w '%{{http_code}}|%{{content_type}}|%{{size_download}}' --max-time {timeout} {url}",
                shell=True, capture_output=True, text=True, timeout=timeout + 2
            )
            parts = result.stdout.strip().split("|")
            status = int(parts[0]) if parts[0].isdigit() else 0
            content_type = parts[1] if len(parts) > 1 else ""
            size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

            if status == 404:
                return None

            interesting = False
            reason = ""
            if status in (200, 201, 204, 301, 302):
                interesting = True
                if "json" in content_type:
                    reason = "JSON API endpoint"
                elif "xml" in content_type:
                    reason = "XML API endpoint"
                elif "graphql" in path:
                    reason = "GraphQL endpoint"
                elif "swagger" in path or "openapi" in path:
                    reason = "API documentation exposed"
                elif ".env" in path or ".git" in path:
                    reason = "SENSITIVE FILE EXPOSED"
                elif "actuator" in path:
                    reason = "Spring Boot actuator exposed"
                elif "admin" in path or "console" in path:
                    reason = "Admin panel found"
                elif "debug" in path or "trace" in path:
                    reason = "Debug endpoint"
                elif "backup" in path or "dump" in path:
                    reason = "Backup file exposed"
                elif status == 301 or status == 302:
                    reason = "Redirect (possible hidden path)"

            return APIEndpoint(
                path=path,
                method="GET",
                status=status,
                content_type=content_type,
                size=size,
                interesting=interesting,
                reason=reason
            )
        except:
            return None
"""
b1pwer.modules.api - Hidden API endpoint discovery
"""
import subprocess
import socket
import re
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class APIEndpoint:
    path: str
    method: str
    status: int
    content_type: str = ""
    size: int = 0
    interesting: bool = False
    reason: str = ""


class APIDiscoverer:
    COMMON_PATHS = [
        "/", "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/auth", "/api/login", "/api/register",
        "/api/admin", "/api/config", "/api/debug", "/api/health",
        "/api/status", "/api/metrics", "/api/internal",
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        "/graphql", "/graphiql", "/playground",
        "/.env", "/.git/config", "/.git/HEAD",
        "/wp-admin", "/wp-login.php", "/xmlrpc.php",
        "/phpmyadmin", "/admin", "/console", "/manager/html",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/actuator/configprops", "/actuator/mappings",
        "/debug", "/trace", "/server-status",
        "/backup", "/db", "/dump", "/sql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/security.txt",
        "/api/swagger", "/v2/api-docs", "/v3/api-docs",
        "/internal", "/private", "/secret", "/hidden",
        "/test", "/dev", "/staging", "/old",
        "/upload", "/uploads", "/files", "/media",
        "/download", "/export", "/import",
        "/webhook", "/webhooks", "/callback", "/notify",
        "/token", "/oauth", "/oauth2", "/saml", "/sso",
        "/session", "/sessions", "/user", "/users",
        "/profile", "/account", "/settings", "/preferences",
        "/search", "/query", "/data", "/report",
    ]

    def scan(self, target: str, scheme: str = "https",
             timeout: float = 1.5, threads: int = 30) -> list:
        """Scan for hidden API endpoints."""
        if not target.startswith("http"):
            target = f"{scheme}://{target}"
        target = target.rstrip("/")

        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._check_path, target, p, timeout): p
                for p in self.COMMON_PATHS
            }
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r and r.status != 404:
                        results.append(r)
                except:
                    pass

        results.sort(key=lambda x: (not x.interesting, x.status, x.path))
        return results

    def _check_path(self, base: str, path: str, timeout: float) -> APIEndpoint | None:
        url = f"{base}{path}"
        try:
            result = subprocess.run(
                f"curl -sk -o /dev/null -w '%{{http_code}}|%{{content_type}}|%{{size_download}}' --max-time {timeout} {url}",
                shell=True, capture_output=True, text=True, timeout=timeout + 2
            )
            parts = result.stdout.strip().split("|")
            status = int(parts[0]) if parts[0].isdigit() else 0
            content_type = parts[1] if len(parts) > 1 else ""
            size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

            if status == 404:
                return None

            interesting = False
            reason = ""
            if status in (200, 201, 204, 301, 302):
                interesting = True
                if "json" in content_type:
                    reason = "JSON API endpoint"
                elif "xml" in content_type:
                    reason = "XML API endpoint"
                elif "graphql" in path:
                    reason = "GraphQL endpoint"
                elif "swagger" in path or "openapi" in path:
                    reason = "API documentation exposed"
                elif ".env" in path or ".git" in path:
                    reason = "SENSITIVE FILE EXPOSED"
                elif "actuator" in path:
                    reason = "Spring Boot actuator exposed"
                elif "admin" in path or "console" in path:
                    reason = "Admin panel found"
                elif "debug" in path or "trace" in path:
                    reason = "Debug endpoint"
                elif "backup" in path or "dump" in path:
                    reason = "Backup file exposed"
                elif status == 301 or status == 302:
                    reason = "Redirect (possible hidden path)"

            return APIEndpoint(
                path=path,
                method="GET",
                status=status,
                content_type=content_type,
                size=size,
                interesting=interesting,
                reason=reason
            )
        except:
            return None
"""
b1pwer.modules.api - Hidden API endpoint discovery
"""
import subprocess
import socket
import re
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class APIEndpoint:
    path: str
    method: str
    status: int
    content_type: str = ""
    size: int = 0
    interesting: bool = False
    reason: str = ""


class APIDiscoverer:
    COMMON_PATHS = [
        "/", "/api", "/api/v1", "/api/v2", "/api/v3",
        "/api/users", "/api/auth", "/api/login", "/api/register",
        "/api/admin", "/api/config", "/api/debug", "/api/health",
        "/api/status", "/api/metrics", "/api/internal",
        "/swagger.json", "/swagger-ui.html", "/swagger-ui/",
        "/openapi.json", "/openapi.yaml", "/api-docs",
        "/graphql", "/graphiql", "/playground",
        "/.env", "/.git/config", "/.git/HEAD",
        "/wp-admin", "/wp-login.php", "/xmlrpc.php",
        "/phpmyadmin", "/admin", "/console", "/manager/html",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/actuator/configprops", "/actuator/mappings",
        "/debug", "/trace", "/server-status",
        "/backup", "/db", "/dump", "/sql",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/security.txt",
        "/api/swagger", "/v2/api-docs", "/v3/api-docs",
        "/internal", "/private", "/secret", "/hidden",
        "/test", "/dev", "/staging", "/old",
        "/upload", "/uploads", "/files", "/media",
        "/download", "/export", "/import",
        "/webhook", "/webhooks", "/callback", "/notify",
        "/token", "/oauth", "/oauth2", "/saml", "/sso",
        "/session", "/sessions", "/user", "/users",
        "/profile", "/account", "/settings", "/preferences",
        "/search", "/query", "/data", "/report",
    ]

    def scan(self, target: str, scheme: str = "https",
             timeout: float = 1.5, threads: int = 30) -> list:
        """Scan for hidden API endpoints."""
        if not target.startswith("http"):
            target = f"{scheme}://{target}"
        target = target.rstrip("/")

        results = []
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(self._check_path, target, p, timeout): p
                for p in self.COMMON_PATHS
            }
            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r and r.status != 404:
                        results.append(r)
                except:
                    pass

        results.sort(key=lambda x: (not x.interesting, x.status, x.path))
        return results

    def _check_path(self, base: str, path: str, timeout: float) -> APIEndpoint | None:
        url = f"{base}{path}"
        try:
            result = subprocess.run(
                f"curl -sk -o /dev/null -w '%{{http_code}}|%{{content_type}}|%{{size_download}}' --max-time {timeout} {url}",
                shell=True, capture_output=True, text=True, timeout=timeout + 2
            )
            parts = result.stdout.strip().split("|")
            status = int(parts[0]) if parts[0].isdigit() else 0
            content_type = parts[1] if len(parts) > 1 else ""
            size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

            if status == 404:
                return None

            interesting = False
            reason = ""
            if status in (200, 201, 204, 301, 302):
                interesting = True
                if "json" in content_type:
                    reason = "JSON API endpoint"
                elif "xml" in content_type:
                    reason = "XML API endpoint"
                elif "graphql" in path:
                    reason = "GraphQL endpoint"
                elif "swagger" in path or "openapi" in path:
                    reason = "API documentation exposed"
                elif ".env" in path or ".git" in path:
                    reason = "SENSITIVE FILE EXPOSED"
                elif "actuator" in path:
                    reason = "Spring Boot actuator exposed"
                elif "admin" in path or "console" in path:
                    reason = "Admin panel found"
                elif "debug" in path or "trace" in path:
                    reason = "Debug endpoint"
                elif "backup" in path or "dump" in path:
                    reason = "Backup file exposed"
                elif status == 301 or status == 302:
                    reason = "Redirect (possible hidden path)"

            return APIEndpoint(
                path=path,
                method="GET",
                status=status,
                content_type=content_type,
                size=size,
                interesting=interesting,
                reason=reason
            )
        except:
            return None
