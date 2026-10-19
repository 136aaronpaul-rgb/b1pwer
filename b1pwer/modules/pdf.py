"""
b1pwer.modules.pdf - Professional PDF report generation
Uses HTML-to-PDF via wkhtmltopdf or fallback to raw HTML print
"""
import subprocess
import os
import json
from datetime import datetime
from typing import Optional


class PDFReporter:
    def __init__(self, output_dir: str = "./b1pwer_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.wkhtmltopdf = self._find_wkhtmltopdf()

    def _find_wkhtmltopdf(self) -> Optional[str]:
        for path in ["/usr/bin/wkhtmltopdf", "/usr/local/bin/wkhtmltopdf", "wkhtmltopdf"]:
            if subprocess.run(f"which {path} > /dev/null 2>&1", shell=True).returncode == 0:
                return path
        return None

    def generate(self, title: str, sections: list, metadata: dict = None) -> str:
        """Generate a PDF report. Falls back to HTML if wkhtmltopdf not available."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = title.replace(" ", "_").replace("/", "_")[:50]
        pdf_path = os.path.join(self.output_dir, f"b1pwer_{safe_title}_{ts}.pdf")

        html = self._build_html(title, sections, metadata)
        html_path = pdf_path.replace(".pdf", ".html")

        with open(html_path, "w") as f:
            f.write(html)

        if self.wkhtmltopdf:
            try:
                subprocess.run(
                    f"{self.wkhtmltopdf} --quiet --enable-local-file-access {html_path} {pdf_path}",
                    shell=True, capture_output=True, timeout=30
                )
                if os.path.isfile(pdf_path):
                    return pdf_path
            except:
                pass

        return html_path

    def _build_html(self, title: str, sections: list, metadata: dict = None) -> str:
        section_html = ""
        for section in sections:
            heading = section.get("heading", "")
            content = section.get("content", "")
            section_html += f"<div class='section'><h2>{heading}</h2>{content}</div>\n"

        meta_html = ""
        if metadata:
            for k, v in metadata.items():
                meta_html += f"<div class='meta-item'><span class='label'>{k}</span><span class='value'>{v}</span></div>\n"

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>b1pwer Report - {title}</title>
<style>
@page {{ size: A4; margin: 20mm; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; font-size: 11px; color: #333; }}
.header {{ background: #1a1a2e; color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
.header h1 {{ margin: 0; font-size: 24px; color: #00d4ff; }}
.header p {{ color: #aaa; margin: 4px 0; font-size: 10px; }}
.meta {{ display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }}
.meta-item {{ background: #f5f5f5; padding: 10px; border-radius: 4px; min-width: 120px; }}
.meta-item .label {{ display: block; color: #888; font-size: 9px; text-transform: uppercase; }}
.meta-item .value {{ font-size: 12px; font-weight: bold; }}
.section {{ background: #fafafa; border: 1px solid #e0e0e0; border-radius: 6px; padding: 15px; margin-bottom: 12px; }}
.section h2 {{ color: #1a1a2e; border-bottom: 2px solid #00d4ff; padding-bottom: 5px; font-size: 14px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
th {{ background: #1a1a2e; color: white; padding: 8px; text-align: left; }}
td {{ padding: 6px; border-bottom: 1px solid #e0e0e0; }}
.critical {{ color: #ff0000; font-weight: bold; }}
.high {{ color: #ff6600; font-weight: bold; }}
.medium {{ color: #ffcc00; }}
.low {{ color: #00cc00; }}
.footer {{ text-align: center; color: #999; font-size: 9px; margin-top: 30px; padding-top: 10px; border-top: 1px solid #e0e0e0; }}
</style></head><body>
<div class="header">
<h1>b1pwer Report</h1>
<p>Aaron Paulos Division | b1pwer.surge.sh</p>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
<div class="meta">{meta_html}</div>
{section_html}
<div class="footer">
<p><b>b1pwer v1.0</b> | Built by Aaron Paulos | Aaron Paulos Division</p>
<p>b1pwer.surge.sh | For authorized security testing only</p>
</div>
</body></html>"""
