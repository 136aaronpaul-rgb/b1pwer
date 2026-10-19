"""
b1pwer.modules.multiplay - Multi-target playbook (scan N targets at once)
"""
import time
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


class MultiPlaybook:
    def __init__(self, output_dir: str = "./b1pwer_reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def run(self, targets: list, profile: str = "quick",
            threads: int = 3, verbose: bool = True) -> dict:
        start = time.time()
        results = {}

        if verbose:
            print(f"\n  Multi-target playbook: {len(targets)} targets, {threads} threads")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {}
            for t in targets:
                f = pool.submit(self._scan_one, t, profile)
                futures[f] = t

            done = 0
            for future in as_completed(futures):
                target = futures[future]
                done += 1
                try:
                    results[target] = future.result()
                    if verbose:
                        r = results[target]
                        print(f"  [{done}/{len(targets)}] {target}: {len(r.get('tcp_ports',[]))} ports, {len(r.get('vulns',[]))} vulns")
                except Exception as e:
                    results[target] = {"error": str(e)}
                    if verbose:
                        print(f"  [{done}/{len(targets)}] {target}: ERROR {e}")

        duration = time.time() - start

        # Combined report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(self.output_dir, f"b1pwer_multi_{ts}.json")
        summary = {
            "tool": "b1pwer",
            "type": "multi_playbook",
            "timestamp": datetime.now().isoformat(),
            "duration": round(duration, 2),
            "targets": len(targets),
            "total_ports": sum(len(r.get("tcp_ports", [])) for r in results.values()),
            "total_vulns": sum(len(r.get("vulns", [])) for r in results.values()),
            "results": results
        }
        with open(report_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)

        if verbose:
            print(f"\n  {'='*50}")
            print(f"  MULTI-TARGET COMPLETE: {len(targets)} targets")
            print(f"  Duration: {duration:.1f}s")
            print(f"  Total Ports: {summary['total_ports']}")
            print(f"  Total Vulns: {summary['total_vulns']}")
            print(f"  Report: {report_path}")
            print(f"  {'='*50}\n")

        return summary

    def _scan_one(self, target: str, profile: str) -> dict:
        from .scanner import B1pwerScanner
        scanner = B1pwerScanner()
        r = scanner.scan(target, profile)
        return {
            "target": r.target,
            "ip": r.ip,
            "tcp_ports": [
                {"port": p.port, "service": p.service, "version": p.version}
                for p in r.ports
            ],
            "vulns": r.vulnerabilities,
            "web_title": r.web_info.get("title", ""),
            "duration": round(r.scan_duration, 2)
        }
