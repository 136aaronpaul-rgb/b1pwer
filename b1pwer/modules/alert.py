"""
b1pwer.modules.alert - Alerting system for critical findings
"""
import json
import os
import subprocess
import urllib.request
import ssl
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class Alert:
    severity: str
    title: str
    detail: str
    target: str
    timestamp: str = ""
    channel: str = ""


class AlertManager:
    def __init__(self, webhook_url: str = "", alert_file: str = None):
        if alert_file is None:
            alert_file = os.path.expanduser("~/.b1pwer/alerts.json")
        self.webhook_url = webhook_url
        self.alert_file = alert_file
        os.makedirs(os.path.dirname(alert_file), exist_ok=True)

    def alert(self, severity: str, title: str, detail: str,
              target: str, channel: str = "") -> Alert:
        a = Alert(
            severity=severity,
            title=title,
            detail=detail,
            target=target,
            timestamp=datetime.now().isoformat(),
            channel=channel
        )
        self._save(a)
        if self.webhook_url and severity in ("CRITICAL", "HIGH"):
            self._send_webhook(a)
        if severity == "CRITICAL":
            self._notify_desktop(a)
        return a

    def _save(self, alert: Alert):
        alerts = []
        if os.path.isfile(self.alert_file):
            try:
                with open(self.alert_file, "r") as f:
                    alerts = json.load(f)
            except:
                alerts = []
        alerts.append({
            "severity": alert.severity,
            "title": alert.title,
            "detail": alert.detail,
            "target": alert.target,
            "time": alert.timestamp
        })
        with open(self.alert_file, "w") as f:
            json.dump(alerts[-100:], f, indent=2)

    def _send_webhook(self, alert: Alert):
        try:
            payload = json.dumps({
                "text": f"[{alert.severity}] {alert.title}\nTarget: {alert.target}\n{alert.detail}"
            }).encode()
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            ctx = ssl.create_default_context()
            urllib.request.urlopen(req, timeout=5, context=ctx)
        except:
            pass

    def _notify_desktop(self, alert: Alert):
        try:
            subprocess.run(
                f"notify-send -u critical 'b1pwer ALERT' '{alert.title} - {alert.target}'",
                shell=True, timeout=3
            )
        except:
            pass

    def get_alerts(self, limit: int = 20) -> list:
        if not os.path.isfile(self.alert_file):
            return []
        try:
            with open(self.alert_file, "r") as f:
                alerts = json.load(f)
            return alerts[-limit:]
        except:
            return []
