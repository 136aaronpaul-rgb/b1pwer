"""
b1pwer - Entry point | 29 modules
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
    parser.add_argument("--api", action="store_true")
    parser.add_argument("--playbook", action="store_true")
    parser.add_argument("--no-nuclei", action="store_true")
    parser.add_argument("--no-cloud", action="store_true")
    parser.add_argument("--alerts", action="store_true")
    parser.add_argument("--brute-ssh", action="store_true", help="Brute force SSH")
    parser.add_argument("--brute-ftp", action="store_true", help="Brute force FTP")
    parser.add_argument("--smb", action="store_true", help="SMB/LDAP enumeration")
    parser.add_argument("--api-server", action="store_true", help="Start REST API server")
    parser.add_argument("--api-port", type=int, default=8443)
    parser.add_argument("--config", action="store_true", help="Show config")
    parser.add_argument("--set-config", default="", help="Set config: b1pwer --set-config 'key=value'")
    parser.add_argument("--plugins", action="store_true", help="List plugins")
    parser.add_argument("--run-plugin", default="", help="Run a plugin")
    parser.add_argument("--forward", default="", help="Port forward: local:remote_host:remote_port")
    parser.add_argument("--export-csv", action="store_true", help="Export last scan to CSV")
    parser.add_argument("--export-xml", action="store_true", help="Export last scan to XML")
    parser.add_argument("--schedule", default="", help="Schedule auto-scan: target [hourly|daily|weekly]")
    parser.add_argument("--unschedule", default="", help="Remove scheduled scan")
    parser.add_argument("--list-schedules", action="store_true", help="List scheduled scans")
    parser.add_argument("--multi", default="", help="Multi-target playbook: comma-separated targets")
    parser.add_argument("--update", action="store_true", help="Check for updates")
    parser.add_argument("--logs", action="store_true", help="Show recent logs")
    parser.add_argument("--ad", action="store_true", help="Active Directory scan")
    parser.add_argument("--ad-user", default="", help="AD username")
    parser.add_argument("--ad-pass", default="", help="AD password")
    parser.add_argument("--container", action="store_true", help="Container/K8s scan")
    parser.add_argument("--iot", action="store_true", help="IoT device discovery")
    parser.add_argument("--proxy", action="store_true", help="Reverse proxy detection")
    parser.add_argument("--dashboard", action="store_true", help="Start web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=9090)
    parser.add_argument("--version", action="version",
                       version="b1pwer v1.0.0 | Aaron Paulos Division")
    args = parser.parse_args()

    from rich.console import Console
    from rich.table import Table
    console = Console()
    console.print(f"[bold cyan]b1pwer v1.0 | Aaron Paulos Division[/bold cyan]\n")

    # API Server
    if args.api_server:
        from .modules.api_server import start_api_server
        start_api_server(args.api_port)
        return

    # Config
    if args.config:
        from .modules.config import ConfigManager
        cm = ConfigManager()
        console.print(f"[bold]Configuration:[/bold]\n{cm.show()}")
        return

    if args.set_config:
        from .modules.config import ConfigManager
        cm = ConfigManager()
        if "=" in args.set_config:
            k, v = args.set_config.split("=", 1)
            cm.set(k.strip(), v.strip())
            console.print(f"[green]Set {k} = {v}[/green]")
        return

    # Plugins
    if args.plugins:
        from .modules.plugins import PluginManager
        pm = PluginManager()
        pm.discover()
        plugins = pm.list()
        if plugins:
            table = Table(title="Plugins")
            table.add_column("Command", style="cyan")
            table.add_column("Name")
            table.add_column("Version")
            table.add_column("Author")
            table.add_column("Description")
            for p in plugins:
                table.add_row(p["command"], p["name"], p["version"], p["author"], p["description"])
            console.print(table)
        else:
            console.print("[yellow]No plugins found. Place .py files in ~/.b1pwer/plugins/[/yellow]")
        return

    if args.run_plugin:
        from .modules.plugins import PluginManager
        pm = PluginManager()
        pm.discover()
        result = pm.run(args.run_plugin, [])
        console.print(result)
        return

    # Brute force
    if args.brute_ssh and args.target:
        from .modules.brute import BruteForcer
        bf = BruteForcer()
        if not bf.available:
            console.print("[red]Hydra not installed (sudo apt install hydra)[/red]")
            return
        console.print(f"[bold magenta]Brute forcing SSH: {args.target}[/bold magenta]\n")
        results = bf.brute_ssh(args.target)
        if results:
            console.print(f"[red]CREDENTIALS FOUND:[/red]")
            for r in results:
                console.print(f"  User: {r.username} | Pass: {r.password}")
        else:
            console.print("[green]No valid credentials found[/green]")
        return

    if args.brute_ftp and args.target:
        from .modules.brute import BruteForcer
        bf = BruteForcer()
        if not bf.available:
            console.print("[red]Hydra not installed[/red]")
            return
        console.print(f"[bold magenta]Brute forcing FTP: {args.target}[/bold magenta]\n")
        results = bf.brute_ftp(args.target)
        if results:
            console.print(f"[red]CREDENTIALS FOUND:[/red]")
            for r in results:
                console.print(f"  User: {r.username} | Pass: {r.password}")
        else:
            console.print("[green]No valid credentials found[/green]")
        return

    # SMB
    if args.smb and args.target:
        from .modules.smb import SMBEnumerator
        smb = SMBEnumerator()
        console.print(f"[bold magenta]SMB Enum: {args.target}[/bold magenta]\n")
        result = smb.enumerate(args.target)
        table = Table(title=f"SMB - {result.target}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Server", result.server_name or "N/A")
        table.add_row("Domain", result.domain or "N/A")
        table.add_row("Workgroup", result.workgroup or "N/A")
        table.add_row("OS", result.os or "N/A")
        table.add_row("Users", ", ".join(result.users[:10]) or "N/A")
        table.add_row("Shares", ", ".join(result.shares[:10]) or "N/A")
        console.print(table)
        return

    # Playbook
    if args.playbook and args.target:
        from .modules.playbook import Playbook
        pb = Playbook(args.output)
        console.print(f"[bold red]PLAYBOOK MODE - Full Assessment[/bold red]")
        console.print(f"  Target: {args.target}")
        console.print(f"  Profile: {args.profile}")
        console.print(f"  Nuclei: {'OFF' if args.no_nuclei else 'ON'}")
        console.print(f"  Cloud:  {'OFF' if args.no_cloud else 'ON'}")
        console.print()
        results = pb.run(
            args.target, profile=args.profile,
            run_nuclei=not args.no_nuclei,
            run_cloud=not args.no_cloud, run_api=True
        )
        return

    # CVE
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
        else:
            console.print(f"[yellow]CVE not found[/yellow]")
        return

    # Audit
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

    # Alerts
    if args.alerts:
        from .modules.alert import AlertManager
        am = AlertManager()
        alerts = am.get_alerts()
        if alerts:
            table = Table(title=f"Alerts ({len(alerts)})")
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

    # History
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

    # Batch
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

    # ARP
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

    # Topology
    if args.topology:
        from .modules.topology import TopologyMapper
        tm = TopologyMapper()
        console.print(f"[bold magenta]Topology: {tm.subnet}[/bold magenta]\n")
        result = tm.map()
        console.print(tm.to_ascii(result))
        return

    # Zone
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
        return

    # Banner
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

    # RDNS
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

    # Sniff
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

    # MSF
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

    # Cloud
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

    # API Discovery
    if args.api and args.target:
        from .modules.api import APIDiscoverer
        ad = APIDiscoverer()
        console.print(f"[bold magenta]API: {args.target}[/bold magenta]\n")
        results = ad.scan(args.target)
        if results:
            table = Table(title=f"Endpoints ({len(results)})")
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

    # Port forward
    if args.forward:
        from .modules.forward import PortForwarder
        pf = PortForwarder()
        parts = args.forward.split(":")
        if len(parts) == 3:
            rule = pf.add(int(parts[0]), parts[1], int(parts[2]))
            pf.start(rule)
            console.print(f"[green]Forwarding 127.0.0.1:{parts[0]} -> {parts[1]}:{parts[2]}[/green]")
            console.print("Press Ctrl+C to stop")
            import time
            try:
                while True: time.sleep(1)
            except KeyboardInterrupt:
                pf.stop_all()
        else:
            console.print("[red]Format: b1pwer --forward LOCAL:REMOTE_HOST:REMOTE_PORT[/red]")
        return

    # Export
    if args.export_csv or args.export_xml:
        from .modules.export import Exporter
        from .modules.history import HistoryDB
        exp = Exporter(args.output)
        db = HistoryDB()
        h = db.get_history(limit=1)
        if h:
            last = h[0]
            if args.export_csv:
                path = exp.to_csv([last], last["target"])
                console.print(f"[green]CSV: {path}[/green]")
            if args.export_xml:
                path = exp.to_xml(last, last["target"])
                console.print(f"[green]XML: {path}[/green]")
        else:
            console.print("[yellow]No scans in history yet[/yellow]")
        db.close()
        return

    # Schedule
    if args.schedule:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        parts = args.schedule.split()
        if len(parts) >= 1:
            target = parts[0]
            sched = parts[1] if len(parts) > 1 else "daily"
            result = sch.add_scan(target, sched)
            console.print(f"[green]{result}[/green]")
        return

    if args.unschedule:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        result = sch.remove_scan(args.unschedule)
        console.print(f"[green]{result}[/green]")
        return

    if args.list_schedules:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        entries = sch.list()
        if entries:
            for e in entries:
                console.print(f"  {e}")
        else:
            console.print("[yellow]No scheduled scans[/yellow]")
        return

    # Multi-target
    if args.multi:
        from .modules.multiplay import MultiPlaybook
        mp = MultiPlaybook(args.output)
        targets = [t.strip() for t in args.multi.split(",") if t.strip()]
        results = mp.run(targets, profile=args.profile, threads=args.threads)
        return

    # Update
    if args.update:
        from .modules.update import Updater
        up = Updater()
        result = up.check()
        console.print(f"  Current: {result['current']}")
        console.print(f"  Latest:  {result['latest']}")
        if result['update_available']:
            console.print(f"  [red]{result['message']}[/red]")
            console.print(f"  URL: {result['url']}")
        else:
            console.print(f"  [green]{result['message']}[/green]")
        return

    # Logs
    if args.logs:
        from .modules.logging_mod import B1pwerLogger
        logger = B1pwerLogger()
        entries = logger.tail(20)
        if entries:
            table = Table(title="Recent Logs")
            table.add_column("Time")
            table.add_column("Level")
            table.add_column("Module")
            table.add_column("Message")
            for e in entries:
                table.add_row(e["time"][:19], e["level"], e["module"], e["message"][:50])
            console.print(table)
        else:
            console.print("[yellow]No logs yet[/yellow]")
        return

    # AD
    if args.ad and args.target:
        from .modules.active_directory import ADScanner
        ad = ADScanner()
        console.print(f"[bold magenta]AD Scan: {args.target}[/bold magenta]
")
        result = ad.scan(args.target, args.ad_user, args.ad_pass)
        table = Table(title=f"AD - {result.domain or args.target}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Domain", result.domain or "N/A")
        table.add_row("Forest", result.forest or "N/A")
        table.add_row("Users", str(len(result.users)))
        table.add_row("Groups", str(len(result.groups)))
        console.print(table)
        if result.users:
            console.print(f"
[bold]Users ({len(result.users)}):[/bold]")
            for u in result.users[:20]:
                console.print(f"  {u}")
        if result.groups:
            console.print(f"
[bold]Groups ({len(result.groups)}):[/bold]")
            for g in result.groups[:20]:
                console.print(f"  {g}")
        return

    # Container
    if args.container:
        from .modules.container import ContainerScanner
        cs = ContainerScanner()
        target = args.target or "127.0.0.1"
        console.print(f"[bold magenta]Container Scan: {target}[/bold magenta]
")
        findings = cs.full_scan(target)
        if findings:
            table = Table(title=f"Containers ({len(findings)})")
            table.add_column("Type")
            table.add_column("Issue")
            table.add_column("Sev", style="bold")
            for f in findings:
                sev_c = "red" if f.severity in ("CRITICAL","HIGH") else "yellow"
                table.add_row(f.container, f.issue, f"[{sev_c}]{f.severity}[/{sev_c}]")
            console.print(table)
        else:
            console.print("[green]No container issues found[/green]")
        return

    # IoT
    if args.iot:
        from .modules.iot import IoTScanner
        iot = IoTScanner()
        console.print(f"[bold magenta]IoT Discovery...[/bold magenta]
")
        devices = iot.discover()
        if devices:
            table = Table(title=f"IoT Devices ({len(devices)})")
            table.add_column("IP", style="cyan")
            table.add_column("Brand")
            table.add_column("Model")
            table.add_column("Services")
            table.add_column("Vulns")
            for d in devices:
                table.add_row(d.ip, d.brand or "-", d.model[:30] or "-", ", ".join(d.services[:3]), str(len(d.vulns)))
            console.print(table)
        else:
            console.print("[yellow]No IoT devices found[/yellow]")
        return

    # Proxy
    if args.proxy and args.target:
        from .modules.proxy import ProxyDetector
        pd = ProxyDetector()
        console.print(f"[bold magenta]Proxy Detection: {args.target}[/bold magenta]
")
        result = pd.detect(args.target)
        table = Table(title=f"Proxy - {result.target}")
        table.add_column("Item")
        table.add_column("Value")
        table.add_row("Proxy Type", result.proxy_type)
        table.add_row("Provider", result.provider or "N/A")
        table.add_row("Origin IP", result.origin_ip or "N/A")
        table.add_row("Server", result.headers.get("server", "N/A"))
        console.print(table)
        return

    # Dashboard
    if args.dashboard:
        from .modules.dashboard import start_dashboard
        start_dashboard(args.dashboard_port)
        return

    if not args.target:
        from .ui.app import B1pwerApp
        B1pwerApp().run()
        return

    # WiFi
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

    # UDP
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

    # Subs
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

    # SSL
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

    # Nuclei
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

    # Standard scan
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
