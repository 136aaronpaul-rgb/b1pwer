"""
b1pwer.modules.plugins - Plugin system for extending b1pwer
Place .py files in ~/.b1pwer/plugins/ to add new modules
"""
import os
import importlib.util
import inspect
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PluginInfo:
    name: str
    version: str
    author: str
    description: str
    command: str
    module: object = None


class PluginManager:
    def __init__(self):
        self.plugins_dir = os.path.expanduser("~/.b1pwer/plugins")
        os.makedirs(self.plugins_dir, exist_ok=True)
        self.plugins = {}

    def discover(self):
        """Find and load all plugins."""
        self.plugins = {}
        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            fpath = os.path.join(self.plugins_dir, fname)
            try:
                spec = importlib.util.spec_from_file_location(fname[:-3], fpath)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                # Look for a class with 'run' method
                for name, obj in inspect.getmembers(mod, inspect.isclass):
                    if hasattr(obj, 'run') and hasattr(obj, 'name'):
                        info = PluginInfo(
                            name=obj.name,
                            version=getattr(obj, 'version', '1.0'),
                            author=getattr(obj, 'author', 'Unknown'),
                            description=getattr(obj, 'description', ''),
                            command=getattr(obj, 'command', name.lower()),
                            module=obj
                        )
                        self.plugins[info.command] = info
                        break
            except Exception as e:
                print(f"  [!] Failed to load plugin {fname}: {e}")

    def run(self, command: str, args: list) -> str:
        """Execute a plugin by command name."""
        if command not in self.plugins:
            return f"Plugin '{command}' not found"
        plugin = self.plugins[command]
        try:
            instance = plugin.module()
            return instance.run(*args)
        except Exception as e:
            return f"Error: {e}"

    def list(self) -> list:
        """List all available plugins."""
        return [
            {"name": p.name, "version": p.version,
             "author": p.author, "description": p.description,
             "command": p.command}
            for p in self.plugins.values()
        ]
