"""
b1pwer.modules.scheduler - Auto-scan scheduling via cron
"""
import subprocess
import os
from datetime import datetime


class Scheduler:
    def __init__(self):
        self.crontab = ""

    def _get_crontab(self) -> str:
        try:
            return subprocess.run(
                "crontab -l 2>/dev/null", shell=True,
                capture_output=True, text=True
            ).stdout
        except:
            return ""

    def add_scan(self, target: str, schedule: str = "daily",
                 profile: str = "standard") -> str:
        """
        schedule: 'hourly', 'daily', 'weekly', or cron expression
        """
        cron_map = {
            "hourly": "0 * * * *",
            "daily": "0 6 * * *",
            "weekly": "0 6 * * 1",
        }
        cron_expr = cron_map.get(schedule, schedule)
        b1pwer_path = os.path.expanduser("~/.local/bin/b1pwer")
        log_dir = os.path.expanduser("~/.b1pwer/logs")
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"auto_{target.replace('.','_')}.log")

        entry = f"{cron_expr} {b1pwer_path} {target} --cli -p {profile} >> {log_file} 2>&1"

        current = self._get_crontab()
        if entry not in current:
            new_cron = current.rstrip() + "\n" + entry + "\n"
            subprocess.run(
                f"echo '{new_cron.rstrip()}' | crontab -",
                shell=True, capture_output=True
            )
            return f"Added: {entry}"
        return "Already exists"

    def remove_scan(self, target: str) -> str:
        current = self._get_crontab()
        lines = [l for l in current.split("\n") if target not in l]
        new_cron = "\n".join(lines)
        subprocess.run(
            f"echo '{new_cron.rstrip()}' | crontab -",
            shell=True, capture_output=True
        )
        return f"Removed scans for {target}"

    def list(self) -> list:
        current = self._get_crontab()
        entries = []
        for line in current.split("\n"):
            if "b1pwer" in line:
                entries.append(line.strip())
        return entries
