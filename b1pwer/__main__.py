"""
b1pwer - Entry point | 24 modules
"""
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(
        prog="b1pwer",
        description="b1pwer - Network Recon & Threat Assessment\nAaron Paulos Division | b1pwer.surge.sh"
    )
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("-p", "--profile", default="quick",
                       choices=["quick","standard","full","aggressive","vuln","discovery"])
    parser.add_argument("-o", "--output", default="./b1pwer_reports")
    parser.add_argument("--cli", action="store_true")
    parser.add_argument("--nuclei", action="store_true")
    parser.add_argument("--nuclei-severity", default="")
    parser.add_argument("--nuclei-tags", default="")
    parser.add_argument("--subs", action="store_true")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--ssl-port", type=int, default=443)
    parser.add_argument("--wifi", action="store_true")
    parser.add_argument("--audit", default="")
    parser.add_argument("--batch", default="")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--compare", default="")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--cve", default="")
    parser.add_argument("--exploits", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--arp", action="store_true")
    parser.add_argument("--topology", action="store_true")
    parser.add_argument("--zone", action="store_true")
    parser.add_argument("--banner", action="store_true")
    parser.add_argument("--rdns", default="")
    parser.add_argument("--sniff", action="store_true")
    parser.add_argument("--sniff-count", type=int, default=50)
    parser.add_argument("--sniff-time", type=int, default=10)
    parser.add_argument("--msf", default="")
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--api", action="store_true", help="API endpoint discovery")
    parser.add_argument("--playbook", action="store_true", help="ONE COMMAND FULL ASSESSMENT")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip nuclei in playbook")
    parser.add_argument("--no-cloud", action="store_true", help="Skip cloud in playbook")
    parser.add_argument("--alerts", action="store_true", help="Show recent alerts")
    parser.add_argument("--version", action="version",
                       version="b1pwer v1.0.0 | Aaron Paulos Division")
    args = parser.parse_args()

    from rich.console import Console
    from rich.table import Table
    console = Console()
    console.print(f"[bold cyan]b1pwer v1.0 | Aaron Paulos Division[/bold cyan]\n")

    # ─── PLAYBOOK (KILLER FEATURE) ───
    if args.playbook and args.target:
        from .modules.playbook import Playbook
        pb = Playbook(args.output)
        console.print(f"[bold red]PLAYBOOK MODE - Full Assessment[/bold red]")
        console.print(f"  Target: {args.target}")
        console.print(f"  Profile: {args.profile}")
        console.print(f"  Nuclei: {'OFF' if args.no_nuclei else 'ON'}")
        console.print(f"  Cloud:  {'OFF' if args.no_cloud else 'ON'}")
        console.print(f"  API:    ON")
        console.print()
        results = pb.run(
            args.target,
            profile=args.profile,
            run_nuclei=not args.no_nuclei,
            run_cloud=not args.no_cloud,
            run_api=True
        )
        return

    # ─── CVE ───
    if args.cve:
        from .modules.cve import CVELookup
        cl = CVELookup()
        info = cl.lookup(args.cve.upper())
        if info:
            table = Table(title=f"CVE: {info.cve_id}")
            table.add_column("Item")
            table.add_column("Value")
            sev_c = "red" if info.cvss_score >= 9 else "yellow" if info.cvss_score >= 5 else "green"
            table.add_row("CVSS", f"[{sev_c}]{info.cvss_score}[/]")
            table.add_row("Severity", info.severity)
            table.add_row("Desc", info.description[:150])
            console.print(table)
            exp = cl.find_exploits(info.cve_id)
            if exp["exploit_available"]:
                console.print(f"\n[red]EXPLOIT AVAILABLE[/red]")
                if exp["exploit_db_id"]:
                    console.print(f"  Exploit-DB: https://www.exploit-db.com/exploits/{exp['exploit_db_id']}")
        else:
            console.print(f"[yellow]CVE not found[/yellow]")
        return

    # ─── AUDIT ───
    if args.audit:
        from .modules.password import PasswordAuditor
        auditor = PasswordAuditor()
        report = auditor.audit(args.audit)
        table = Table(title="Password Audit")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Length", str(report.length))
        table.add_row("Entropy", f"{report.entropy:.1f} bits")
        table.add_row("Crack Time", report.crack_time)
        sc = "green" if report.score >= 80 else "yellow" if report.score >= 50 else "red"
        table.add_row("SCORE", f"[{sc}]{report.score}/100[/{sc}]")
        table.add_row("Breach", "[red]YES[/red]" if report.in_breach else "[green]No[/green]")
        console.print(table)
        for i in report.issues:
            console.print(f"  [red]x {i}[/red]")
        for s in report.suggestions:
            console.print(f"  [green]-> {s}[/green]")
        return

    # ─── ALERTS ───
    if args.alerts:
        from .modules.alert import AlertManager
        am = AlertManager()
        alerts = am.get_alerts()
        if alerts:
            table = Table(title=f"Recent Alerts ({len(alerts)})")
            table.add_column("Time")
            table.add_column("Sev", style="bold")
            table.add_column("Title")
            table.add_column("Target")
            for a in alerts:
                c = "red" if a["severity"] in ("CRITICAL","HIGH") else "yellow"
                table.add_row(a["time"][:19], f"[{c}]{a['severity']}[/{c}]", a["title"][:40], a["target"])
            console.print(table)
        else:
            console.print("[yellow]No alerts[/yellow]")
        return

    # ─── HISTORY/COMPARE/STATS ───
    if args.history or args.compare or args.stats:
        from .modules.history import HistoryDB
        db = HistoryDB()
        if args.stats:
            s = db.stats()
            console.print(f"  Scans: {s['total_scans']} | Targets: {s['unique_targets']} | Vulns: {s['scans_with_vulns']}")
        if args.compare:
            c = db.compare(args.compare)
            if "error" in c:
                console.print(f"[yellow]{c['error']}[/yellow]")
            else:
                console.print(f"[bold]{c['target']}[/bold]: {c['scan_1']} vs {c['scan_2']}")
                if c['new_ports']: console.print(f"  [red]NEW: {c['new_ports']}[/red]")
                if c['closed_ports']: console.print(f"  [green]Closed: {c['closed_ports']}[/green]")
                if c['new_vulns']: console.print(f"  [red]NEW vulns: {c['new_vulns']}[/red]")
        if args.history:
            h = db.get_history(limit=20)
            if h:
                table = Table(title="History")
                table.add_column("Time")
                table.add_column("Target", style="cyan")
                table.add_column("Ports")
                table.add_column("Vulns")
                for item in h:
                    vc = "red" if item['vulns'] else "green"
                    table.add_row(item['time'][:19], item['target'], str(len(item['ports'])), f"[{vc}]{len(item['vulns'])}[/{vc}]")
                console.print(table)
            else:
                console.print("[yellow]No history[/yellow]")
        db.close()
        return

    # ─── BATCH ───
    if args.batch:
        from .modules.batch import BatchScanner
        bs = BatchScanner(max_threads=args.threads)
        targets = bs.load_targets(args.batch)
        console.print(f"[bold magenta]BATCH: {len(targets)} targets[/bold magenta]\n")
        results = bs.scan_batch(targets, profile=args.profile, threads=args.threads)
        table = Table(title=f"Batch ({len(results)})")
        table.add_column("Target", style="cyan")
        table.add_column("IP")
        table.add_column("Ports")
        table.add_column("Vulns", style="bold")
        for r in results:
            vc = "red" if r.vulns else "green"
            table.add_row(r.target, r.ip, str(len(r.open_ports)), f"[{vc}]{len(r.vulns)}[/{vc}]")
        console.print(table)
        console.print(f"\n[green]Report: {bs.save_report(results, args.output)}[/green]")
        return

    # ─── ARP ───
    if args.arp:
        from .modules.arp import ARPScanner
        ar = ARPScanner()
        subnet = ar.get_local_subnet()
        console.print(f"[bold magenta]ARP: {subnet}[/bold magenta]\n")
        entries = ar.scan(subnet)
        if entries:
            table = Table(title=f"ARP ({len(entries)})")
            table.add_column("IP", style="cyan")
            table.add_column("MAC")
            table.add_column("Vendor")
            table.add_column("Hostname")
            for e in entries:
                table.add_row(e.ip, e.mac, e.vendor or "-", e.hostname or "-")
            console.print(table)
        return

    # ─── TOPOLOGY ───
    if args.topology:
        from .modules.topology import TopologyMapper
        tm = TopologyMapper()
        console.print(f"[bold magenta]Topology: {tm.subnet}[/bold magenta]\n")
        result = tm.map()
        console.print(tm.to_ascii(result))
        return

    # ─── DNS ZONE ───
    if args.zone and args.target:
        from .modules.dnszone import DNSZoneScanner
        dz = DNSZoneScanner()
        console.print(f"[bold magenta]DNS Zone: {args.target}[/bold magenta]\n")
        result = dz.scan(args.target)
        console.print(f"  NS: {', '.join(result['nameservers']) or 'N/A'}")
        if result["axfr_success"]:
            console.print(f"  [red]AXFR OPEN! ({len(result['axfr_records'])} records)[/red]")
        else:
            console.print(f"  [green]AXFR blocked[/green]")
        if result["brute_subdomains"]:
            console.print(f"\n  Subs: {len(result['brute_subdomains'])} found")
            for r in result["brute_subdomains"][:10]:
                console.print(f"    {r.name} → {r.value}")
        return

    # ─── BANNER ───
    if args.banner and args.target:
        from .modules.banner import BannerGrabber
        bg = BannerGrabber()
        console.print(f"[bold magenta]Banners: {args.target}[/bold magenta]\n")
        results = bg.grab(args.target)
        if results:
            table = Table(title=f"Banners ({len(results)})")
            table.add_column("Port", style="yellow")
            table.add_column("Service")
            table.add_column("Version")
            table.add_column("OS")
            for r in results:
                table.add_row(str(r.port), r.service, r.version or "-", r.os_hint or "-")
            console.print(table)
        return

    # ─── RDNS ───
    if args.rdns:
        from .modules.reverse import ReverseDNS
        rd = ReverseDNS()
        if "/" in args.rdns:
            results = rd.lookup_range(args.rdns)
        else:
            results = rd.lookup_list([args.rdns])
        if results:
            table = Table(title=f"PTR ({len(results)})")
            table.add_column("IP", style="cyan")
            table.add_column("Hostname", style="green")
            for r in results:
                table.add_row(r.ip, r.hostname)
            console.print(table)
        else:
            console.print("[yellow]No PTR records[/yellow]")
        return

    # ─── SNIFF ───
    if args.sniff:
        from .modules.packet import PacketSniffer
        ps = PacketSniffer()
        console.print(f"[bold magenta]Sniffing {args.sniff_count} packets...[/bold magenta]\n")
        packets = ps.capture(count=args.sniff_count, duration=args.sniff_time)
        if packets:
            table = Table(title=f"Packets ({len(packets)})")
            table.add_column("Src", style="cyan")
            table.add_column("Dst", style="cyan")
            table.add_column("Proto")
            table.add_column("Len")
            for p in packets[:30]:
                table.add_row(p.src_ip, p.dst_ip, p.protocol, str(p.length))
            console.print(table)
        else:
            console.print("[yellow]No packets (need root)[/yellow]")
        return

    # ─── MSF ───
    if args.msf:
        from .modules.msf import MetasploitController
        msf = MetasploitController()
        if not msf.available:
            console.print("[red]Metasploit not installed[/red]")
            return
        console.print(f"[bold magenta]MSF: {args.msf}[/bold magenta]\n")
        modules = msf.search(args.msf)
        if modules:
            table = Table(title=f"Modules ({len(modules)})")
            table.add_column("Module", style="cyan")
            table.add_column("Type")
            table.add_column("Rank")
            for m in modules[:20]:
                table.add_row(m.name, m.type, m.rank)
            console.print(table)
        return

    # ─── CLOUD ───
    if args.cloud and args.target:
        from .modules.cloud import CloudScanner
        cs = CloudScanner()
        console.print(f"[bold magenta]Cloud: {args.target}[/bold magenta]\n")
        findings = cs.full_scan(args.target)
        if findings:
            table = Table(title=f"Cloud ({len(findings)})")
            table.add_column("Provider")
            table.add_column("Resource", style="cyan")
            table.add_column("Issue")
            table.add_column("Sev", style="bold")
            for f in findings:
                sev_c = "red" if f.severity in ("CRITICAL","HIGH") else "yellow"
                table.add_row(f.provider, f.resource, f.issue, f"[{sev_c}]{f.severity}[/{sev_c}]")
            console.print(table)
        else:
            console.print("[green]Clean[/green]")
        return

    # ─── API ───
    if args.api and args.target:
        from .modules.api import APIDiscoverer
        ad = APIDiscoverer()
        console.print(f"[bold magenta]API Discovery: {args.target}[/bold magenta]\n")
        results = ad.scan(args.target)
        if results:
            table = Table(title=f"API Endpoints ({len(results)})")
            table.add_column("Path", style="cyan")
            table.add_column("Status")
            table.add_column("Reason")
            for r in results:
                st_c = "green" if r.status == 200 else "yellow"
                table.add_row(r.path, f"[{st_c}]{r.status}[/{st_c}]", r.reason or "-")
            console.print(table)
        else:
            console.print("[yellow]No endpoints found[/yellow]")
        return

    if not args.target:
        from .ui.app import B1pwerApp
        B1pwerApp().run()
        return

    # ─── WiFi ───
    if args.wifi:
        from .modules.wifi import WiFiScanner
        wf = WiFiScanner()
        if not wf.wlan:
            console.print("[red]No WiFi interface[/red]")
            return
        console.print(f"[bold magenta]WiFi: {wf.wlan}[/bold magenta]\n")
        nets = wf.scan()
        if nets:
            table = Table(title=f"WiFi ({len(nets)})")
            table.add_column("SSID", style="cyan")
            table.add_column("BSSID")
            table.add_column("Ch")
            table.add_column("Signal")
            table.add_column("Enc")
            for n in nets:
                enc = "[red]Open[/red]" if n.encryption == "Open" else "[green]WPA[/green]"
                table.add_row(n.ssid, n.bssid, str(n.channel), f"{n.signal}dBm", enc)
            console.print(table)
        return

    # ─── UDP ───
    if args.udp:
        from .modules.udp import UDPScanner
        us = UDPScanner()
        console.print(f"[bold magenta]UDP: {args.target}[/bold magenta]\n")
        results = us.scan(args.target)
        open_ports = [r for r in results if r.state in ("open", "open|filtered")]
        table = Table(title=f"UDP ({len(open_ports)})")
        table.add_column("Port", style="yellow")
        table.add_column("State")
        table.add_column("Service")
        for r in open_ports:
            st_c = "green" if r.state == "open" else "yellow"
            table.add_row(str(r.port), f"[{st_c}]{r.state}[/{st_c}]", r.service or "-")
        console.print(table)
        return

    # ─── SUBS ───
    if args.subs:
        from .modules.subdomains import SubdomainScanner
        ss = SubdomainScanner()
        console.print(f"[bold magenta]Subs: {args.target}[/bold magenta]\n")
        subs = ss.scan(args.target)
        if subs:
            table = Table(title=f"Subs ({len(subs)})")
            table.add_column("Name", style="cyan")
            table.add_column("IP", style="yellow")
            for s in subs:
                table.add_row(s.name, s.ip or "-")
            console.print(table)
        return

    # ─── SSL ───
    if args.ssl:
        from .modules.ssl import SSLScanner
        sa = SSLScanner()
        console.print(f"[bold magenta]SSL: {args.target}[/bold magenta]\n")
        result = sa.audit(args.target, args.ssl_port)
        table = Table(title=f"SSL - {result.hostname}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Protocol", result.protocol or "N/A")
        table.add_row("Key", f"{result.key_size} bits")
        table.add_row("Days Left", str(result.days_remaining))
        sc = "green" if result.score >= 80 else "yellow" if result.score >= 50 else "red"
        table.add_row("SCORE", f"[{sc}]{result.score}/100[/{sc}]")
        console.print(table)
        return

    # ─── NUCLEI ───
    if args.nuclei:
        from .modules.nuclei import NucleiScanner
        nuclei = NucleiScanner()
        if not nuclei.available:
            console.print("[red]Nuclei not found[/red]")
            return
        console.print(f"[bold magenta]Nuclei: {args.target}[/bold magenta]\n")
        findings = nuclei.scan(args.target, severity=args.nuclei_severity, tags=args.nuclei_tags)
        if findings:
            table = Table(title=f"Findings ({len(findings)})")
            table.add_column("Sev", style="bold")
            table.add_column("ID")
            table.add_column("Name")
            for f in sorted(findings, key=lambda x:{"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(f.severity,5)):
                c = {"critical":"red","high":"red","medium":"yellow","low":"green","info":"dim"}.get(f.severity,"white")
                table.add_row(f"[{c}]{f.severity.upper()}[/{c}]", f.cve or f.template_id[:25], f.name[:50])
            console.print(table)
        else:
            console.print("[green]Clean[/green]")
        return

    # ─── STANDARD SCAN ───
    from .modules.scanner import B1pwerScanner
    from .modules.reporter import Reporter
    scanner = B1pwerScanner()
    reporter = Reporter(args.output)
    console.print(f"Scanning [bold]{args.target}[/bold] | {args.profile}\n")
    result = scanner.scan(args.target, args.profile)
    table = Table(title=f"Ports - {result.target}")
    table.add_column("Port", style="yellow")
    table.add_column("Proto")
    table.add_column("State", style="green")
    table.add_column("Service")
    table.add_column("Version")
    for p in result.ports:
        table.add_row(str(p.port), p.protocol, p.state, p.service, p.version)
    console.print(table)
    console.print(f"\n[green]{len(result.ports)} open | {len(result.vulnerabilities)} vulns | {result.scan_duration:.1f}s[/green]")

    if args.exploits and result.ports:
        from .modules.exploit import ExploitSuggester
        es = ExploitSuggester()
        suggestions = es.suggest(result.ports)
        if suggestions:
            console.print(f"\n[bold red]EXPLOITS ({len(suggestions)}):[/bold red]")
            table2 = Table(title="Known Exploits")
            table2.add_column("Port")
            table2.add_column("CVE", style="red")
            table2.add_column("Sev", style="bold")
            table2.add_column("Metasploit")
            for s in suggestions:
                sev_c = "red" if s.severity == "CRITICAL" else "yellow" if s.severity == "HIGH" else "green"
                table2.add_row(str(s.port), s.cve, f"[{sev_c}]{s.severity}[/{sev_c}]", s.msf_module or "-")
            console.print(table2)

    paths = reporter.save_all(result)
    for fmt, path in paths.items():
        console.print(f"  {fmt}: {path}")

    from .modules.history import HistoryDB
    db = HistoryDB()
    db.save_scan(
        target=result.target, ip=result.ip, profile=args.profile,
        ports=[f"{p.port}/{p.protocol}" for p in result.ports],
        services=[f"{p.service} {p.version}".strip() for p in result.ports],
        vulns=[f"[{v['severity']}] {v['script']}:{v['port']}" for v in result.vulnerabilities],
        web_title=result.web_info.get("title", ""),
        duration=result.scan_duration
    )
    db.close()

if __name__ == "__main__":
    main()
