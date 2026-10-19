"""
b1pwer.modules.update - Check for updates from GitHub
"""
import json
import subprocess
import urllib.request
import ssl
from .. import __version__


class Updater:
    REPO = "136aaronpaul-rgb/b1pwer"
    API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"

    def check(self) -> dict:
        result = {
            "current": __version__,
            "latest": __version__,
            "update_available": False,
            "url": "",
            "message": ""
        }
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                self.API_URL,
                headers={"User-Agent": "b1pwer/1.0", "Accept": "application/vnd.github.v3+json"}
            )
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            data = json.loads(resp.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            result["latest"] = latest
            result["url"] = data.get("html_url", "")
            if latest != __version__:
                result["update_available"] = True
                result["message"] = f"New version {latest} available!"
            else:
                result["message"] = "You're on the latest version."
        except Exception as e:
            result["message"] = f"Could not check: {e}"
        return result

    def update(self) -> str:
        try:
            result = subprocess.run(
                "cd ~/b1pwer && git pull && pip install -e . 2>&1",
                shell=True, capture_output=True, text=True, timeout=60
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Update failed: {e}"
