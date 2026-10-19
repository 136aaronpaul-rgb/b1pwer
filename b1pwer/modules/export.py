"""
b1pwer.modules.export - CSV and XML report export
"""
import csv
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from xml.dom import minidom


class Exporter:
    def __init__(self, output_dir: str = "./b1pwer_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def to_csv(self, results: list, target: str = "scan") -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"b1pwer_{target}_{ts}.csv")
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "ip", "port", "protocol", "service", "version", "severity", "vuln"])
            for r in results:
                writer.writerow([
                    r.get("target", ""),
                    r.get("ip", ""),
                    r.get("port", ""),
                    r.get("protocol", ""),
                    r.get("service", ""),
                    r.get("version", ""),
                    r.get("severity", ""),
                    r.get("vuln", "")
                ])
        return path

    def to_xml(self, data: dict, target: str = "scan") -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"b1pwer_{target}_{ts}.xml")
        root = ET.Element("b1pwer_report")
        root.set("tool", "b1pwer")
        root.set("version", "1.0.0")
        root.set("author", "Aaron Paulos")
        root.set("timestamp", datetime.now().isoformat())
        self._dict_to_xml(root, data)
        rough = ET.tostring(root, encoding="unicode")
        pretty = minidom.parseString(rough).toprettyxml(indent="  ")
        with open(path, "w") as f:
            f.write(pretty)
        return path

    def _dict_to_xml(self, parent: ET.Element, data: dict):
        for key, value in data.items():
            elem = ET.SubElement(parent, key.replace(" ", "_").replace("-", "_"))
            if isinstance(value, dict):
                self._dict_to_xml(elem, value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(elem, "item")
                        self._dict_to_xml(item_elem, item)
                    else:
                        ET.SubElement(elem, "item").text = str(item)
            else:
                elem.text = str(value)
