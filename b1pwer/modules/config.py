"""
b1pwer.modules.config - Configuration management
"""
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Config:
    default_profile: str = "quick"
    default_threads: int = 5
    output_dir: str = "./b1pwer_reports"
    nuclei_severity: str = ""
    nuclei_tags: str = ""
    webhook_url: str = ""
    auto_history: bool = True
    auto_alerts: bool = True
    timeout: float = 5.0
    user_agent: str = "b1pwer/1.0"
    theme: str = "dark"
    log_level: str = "INFO"


class ConfigManager:
    def __init__(self):
        self.config_path = os.path.expanduser("~/.b1pwer/config.json")
        self.config = Config()
        self._load()

    def _load(self):
        if os.path.isfile(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        if hasattr(self.config, k):
                            setattr(self.config, k, v)
            except:
                pass

    def save(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(asdict(self.config), f, indent=2)

    def get(self, key: str):
        return getattr(self.config, key, None)

    def set(self, key: str, value):
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self.save()

    def show(self) -> str:
        lines = []
        for k, v in asdict(self.config).items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)
