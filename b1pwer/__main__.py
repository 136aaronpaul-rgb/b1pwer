"""
b1pwer - Entry point | 40 modules
"""
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(prog="b1pwer")
    parser.add_argument("target", nargs="?")
    parser.add_argument("-p", "--profile", default="quick", choices=["quick","standard","full","aggressive","vuln","discovery"])
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
    parser.add_argument("--brute-ssh", action="store_true")
    parser.add_argument("--brute-ftp", action="store_true")
    parser.add_argument("--smb", action="store_true")
    parser.add_argument("--api-server", action="store_true")
    parser.add_argument("--api-port", type=int, default=8443)
    parser.add_argument("--config", action="store_true")
    parser.add_argument("--set-config", default="")
    parser.add_argument("--plugins", action="store_true")
    parser.add_argument("--run-plugin", default="")
    parser.add_argument("--forward", default="")
    parser.add_argument("--export-csv", action="store_true")
    parser.add_argument("--export-xml", action="store_true")
    parser.add_argument("--schedule", default="")
    parser.add_argument("--unschedule", default="")
    parser.add_argument("--list-schedules", action="store_true")
    parser.add_argument("--multi", default="")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--logs", action="store_true")
    parser.add_argument("--ad", action="store_true")
    parser.add_argument("--ad-user", default="")
    parser.add_argument("--ad-pass", default="")
    parser.add_argument("--container", action="store_true")
    parser.add_argument("--iot", action="store_true")
    parser.add_argument("--proxy", action="store_true")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--dashboard-port", type=int, default=9090)
    parser.add_argument("--version", action="version", version="b1pwer v1.0.0")
    args = parser.parse_args()

    from rich.console import Console
    from rich.table import Table
    console = Console()
    console.print("[bold cyan]b1pwer v1.0 | Aaron Paulos Division[/bold cyan]")
    console.print()

    if args.api_server:
        from .modules.api_server import start_api_server
        start_api_server(args.api_port)
        return
    if args.config:
        from .modules.config import ConfigManager
        cm = ConfigManager()
        console.print("[bold]Config:[/bold]")
        console.print(cm.show())
        return
    if args.set_config:
        from .modules.config import ConfigManager
        cm = ConfigManager()
        if "=" in args.set_config:
            k, v = args.set_config.split("=", 1)
            cm.set(k.strip(), v.strip())
            console.print("[green]Set " + k + "=" + v + "[/green]")
        return
    if args.plugins:
        from .modules.plugins import PluginManager
        pm = PluginManager()
        pm.discover()
        plugins = pm.list()
        if plugins:
            t = Table(title="Plugins")
            t.add_column("Cmd", style="cyan")
            t.add_column("Name")
            t.add_column("Ver")
            t.add_column("Author")
            for p in plugins:
                t.add_row(p["command"], p["name"], p["version"], p["author"])
            console.print(t)
        else:
            console.print("[yellow]No plugins[/yellow]")
        return
    if args.run_plugin:
        from .modules.plugins import PluginManager
        pm = PluginManager()
        pm.discover()
        console.print(pm.run(args.run_plugin, []))
        return
    if args.brute_ssh and args.target:
        from .modules.brute import BruteForcer
        bf = BruteForcer()
        if not bf.available:
            console.print("[red]Hydra not installed[/red]")
            return
        console.print("[bold magenta]Brute SSH: " + args.target + "[/bold magenta]")
        results = bf.brute_ssh(args.target)
        if results:
            console.print("[red]FOUND:[/red]")
            for r in results:
                console.print("  " + r.username + " : " + r.password)
        else:
            console.print("[green]None found[/green]")
        return
    if args.brute_ftp and args.target:
        from .modules.brute import BruteForcer
        bf = BruteForcer()
        if not bf.available:
            console.print("[red]Hydra not installed[/red]")
            return
        console.print("[bold magenta]Brute FTP: " + args.target + "[/bold magenta]")
        results = bf.brute_ftp(args.target)
        if results:
            console.print("[red]FOUND:[/red]")
            for r in results:
                console.print("  " + r.username + " : " + r.password)
        else:
            console.print("[green]None found[/green]")
        return
    if args.smb and args.target:
        from .modules.smb import SMBEnumerator
        smb = SMBEnumerator()
        console.print("[bold magenta]SMB: " + args.target + "[/bold magenta]")
        result = smb.enumerate(args.target)
        t = Table(title="SMB")
        t.add_column("Item")
        t.add_column("Value")
        t.add_row("Server", result.server_name or "N/A")
        t.add_row("Domain", result.domain or "N/A")
        t.add_row("Users", str(len(result.users)))
        t.add_row("Shares", str(len(result.shares)))
        console.print(t)
        return
    if args.ad and args.target:
        from .modules.active_directory import ADScanner
        ad = ADScanner()
        console.print("[bold magenta]AD: " + args.target + "[/bold magenta]")
        result = ad.scan(args.target, args.ad_user, args.ad_pass)
        t = Table(title="AD")
        t.add_column("Item")
        t.add_column("Value")
        t.add_row("Domain", result.domain or "N/A")
        t.add_row("Users", str(len(result.users)))
        t.add_row("Groups", str(len(result.groups)))
        console.print(t)
        return
    if args.container:
        from .modules.container import ContainerScanner
        cs = ContainerScanner()
        target = args.target or "127.0.0.1"
        console.print("[bold magenta]Container: " + target + "[/bold magenta]")
        findings = cs.full_scan(target)
        if findings:
            t = Table(title="Containers")
            t.add_column("Type")
            t.add_column("Issue")
            t.add_column("Sev")
            for f in findings:
                t.add_row(f.container, f.issue, f.severity)
            console.print(t)
        else:
            console.print("[green]Clean[/green]")
        return
    if args.iot:
        from .modules.iot import IoTScanner
        iot = IoTScanner()
        console.print("[bold magenta]IoT Discovery...[/bold magenta]")
        devices = iot.discover()
        if devices:
            t = Table(title="IoT (" + str(len(devices)) + ")")
            t.add_column("IP", style="cyan")
            t.add_column("Brand")
            t.add_column("Services")
            for d in devices:
                t.add_row(d.ip, d.brand or "-", ", ".join(d.services[:3]))
            console.print(t)
        else:
            console.print("[yellow]No IoT found[/yellow]")
        return
    if args.proxy and args.target:
        from .modules.proxy import ProxyDetector
        pd = ProxyDetector()
        console.print("[bold magenta]Proxy: " + args.target + "[/bold magenta]")
        result = pd.detect(args.target)
        t = Table(title="Proxy")
        t.add_column("Item")
        t.add_column("Value")
        t.add_row("Type", result.proxy_type)
        t.add_row("Provider", result.provider or "N/A")
        t.add_row("Origin", result.origin_ip or "N/A")
        console.print(t)
        return
    if args.dashboard:
        from .modules.dashboard import start_dashboard
        start_dashboard(args.dashboard_port)
        return
    if args.playbook and args.target:
        from .modules.playbook import Playbook
        pb = Playbook(args.output)
        console.print("[bold red]PLAYBOOK MODE[/bold red]")
        pb.run(args.target, profile=args.profile, run_nuclei=not args.no_nuclei, run_cloud=not args.no_cloud, run_api=True)
        return
    if args.multi:
        from .modules.multiplay import MultiPlaybook
        mp = MultiPlaybook(args.output)
        targets = [t.strip() for t in args.multi.split(",") if t.strip()]
        mp.run(targets, profile=args.profile, threads=args.threads)
        return
    if args.cve:
        from .modules.cve import CVELookup
        cl = CVELookup()
        info = cl.lookup(args.cve.upper())
        if info:
            t = Table(title="CVE: " + info.cve_id)
            t.add_column("Item")
            t.add_column("Value")
            t.add_row("CVSS", str(info.cvss_score))
            t.add_row("Severity", info.severity)
            t.add_row("Desc", info.description[:150])
            console.print(t)
        else:
            console.print("[yellow]Not found[/yellow]")
        return
    if args.audit:
        from .modules.password import PasswordAuditor
        auditor = PasswordAuditor()
        report = auditor.audit(args.audit)
        t = Table(title="Password Audit")
        t.add_column("Item")
        t.add_column("Value")
        t.add_row("Length", str(report.length))
        t.add_row("Entropy", str(round(report.entropy, 1)) + " bits")
        t.add_row("Crack Time", report.crack_time)
        t.add_row("SCORE", str(report.score) + "/100")
        t.add_row("Breach", "YES" if report.in_breach else "No")
        console.print(t)
        for i in report.issues:
            console.print("  [red]x " + i + "[/red]")
        for s in report.suggestions:
            console.print("  [green]-> " + s + "[/green]")
        return
    if args.alerts:
        from .modules.alert import AlertManager
        am = AlertManager()
        alerts = am.get_alerts()
        if alerts:
            t = Table(title="Alerts")
            t.add_column("Time")
            t.add_column("Sev")
            t.add_column("Title")
            for a in alerts:
                t.add_row(a["time"][:19], a["severity"], a["title"][:40])
            console.print(t)
        else:
            console.print("[yellow]No alerts[/yellow]")
        return
    if args.history or args.compare or args.stats:
        from .modules.history import HistoryDB
        db = HistoryDB()
        if args.stats:
            s = db.stats()
            console.print("  Scans: " + str(s["total_scans"]) + " | Targets: " + str(s["unique_targets"]))
        if args.compare:
            c = db.compare(args.compare)
            if "error" in c:
                console.print("[yellow]" + c["error"] + "[/yellow]")
            else:
                console.print("[bold]" + c["target"] + "[/bold]")
                if c["new_ports"]: console.print("  [red]NEW: " + str(c["new_ports"]) + "[/red]")
                if c["closed_ports"]: console.print("  [green]Closed: " + str(c["closed_ports"]) + "[/green]")
        if args.history:
            h = db.get_history(limit=20)
            if h:
                t = Table(title="History")
                t.add_column("Time")
                t.add_column("Target", style="cyan")
                t.add_column("Ports")
                t.add_column("Vulns")
                for item in h:
                    t.add_row(item["time"][:19], item["target"], str(len(item["ports"])), str(len(item["vulns"])))
                console.print(t)
            else:
                console.print("[yellow]No history[/yellow]")
        db.close()
        return
    if args.batch:
        from .modules.batch import BatchScanner
        bs = BatchScanner(max_threads=args.threads)
        targets = bs.load_targets(args.batch)
        console.print("[bold magenta]BATCH: " + str(len(targets)) + " targets[/bold magenta]")
        results = bs.scan_batch(targets, profile=args.profile, threads=args.threads)
        t = Table(title="Batch")
        t.add_column("Target", style="cyan")
        t.add_column("IP")
        t.add_column("Ports")
        t.add_column("Vulns")
        for r in results:
            t.add_row(r.target, r.ip, str(len(r.open_ports)), str(len(r.vulns)))
        console.print(t)
        return
    if args.arp:
        from .modules.arp import ARPScanner
        ar = ARPScanner()
        subnet = ar.get_local_subnet()
        console.print("[bold magenta]ARP: " + subnet + "[/bold magenta]")
        entries = ar.scan(subnet)
        if entries:
            t = Table(title="ARP")
            t.add_column("IP", style="cyan")
            t.add_column("MAC")
            t.add_column("Vendor")
            for e in entries:
                t.add_row(e.ip, e.mac, e.vendor or "-")
            console.print(t)
        return
    if args.topology:
        from .modules.topology import TopologyMapper
        tm = TopologyMapper()
        console.print("[bold magenta]Topology: " + tm.subnet + "[/bold magenta]")
        result = tm.map()
        console.print(tm.to_ascii(result))
        return
    if args.zone and args.target:
        from .modules.dnszone import DNSZoneScanner
        dz = DNSZoneScanner()
        console.print("[bold magenta]Zone: " + args.target + "[/bold magenta]")
        result = dz.scan(args.target)
        console.print("  NS: " + (", ".join(result["nameservers"]) or "N/A"))
        if result["axfr_success"]:
            console.print("  [red]AXFR OPEN![/red]")
        else:
            console.print("  [green]AXFR blocked[/green]")
        return
    if args.banner and args.target:
        from .modules.banner import BannerGrabber
        bg = BannerGrabber()
        console.print("[bold magenta]Banners: " + args.target + "[/bold magenta]")
        results = bg.grab(args.target)
        if results:
            t = Table(title="Banners")
            t.add_column("Port", style="yellow")
            t.add_column("Service")
            t.add_column("Version")
            for r in results:
                t.add_row(str(r.port), r.service, r.version or "-")
            console.print(t)
        return
    if args.rdns:
        from .modules.reverse import ReverseDNS
        rd = ReverseDNS()
        if "/" in args.rdns:
            results = rd.lookup_range(args.rdns)
        else:
            results = rd.lookup_list([args.rdns])
        if results:
            t = Table(title="PTR")
            t.add_column("IP", style="cyan")
            t.add_column("Hostname", style="green")
            for r in results:
                t.add_row(r.ip, r.hostname)
            console.print(t)
        else:
            console.print("[yellow]No PTR[/yellow]")
        return
    if args.sniff:
        from .modules.packet import PacketSniffer
        ps = PacketSniffer()
        console.print("[bold magenta]Sniffing...[/bold magenta]")
        packets = ps.capture(count=args.sniff_count, duration=args.sniff_time)
        if packets:
            t = Table(title="Packets (" + str(len(packets)) + ")")
            t.add_column("Src", style="cyan")
            t.add_column("Dst", style="cyan")
            t.add_column("Proto")
            for p in packets[:30]:
                t.add_row(p.src_ip, p.dst_ip, p.protocol)
            console.print(t)
        else:
            console.print("[yellow]No packets (need root)[/yellow]")
        return
    if args.msf:
        from .modules.msf import MetasploitController
        msf = MetasploitController()
        if not msf.available:
            console.print("[red]Metasploit not installed[/red]")
            return
        console.print("[bold magenta]MSF: " + args.msf + "[/bold magenta]")
        modules = msf.search(args.msf)
        if modules:
            t = Table(title="Modules")
            t.add_column("Module", style="cyan")
            t.add_column("Type")
            t.add_column("Rank")
            for m in modules[:20]:
                t.add_row(m.name, m.type, m.rank)
            console.print(t)
        return
    if args.cloud and args.target:
        from .modules.cloud import CloudScanner
        cs = CloudScanner()
        console.print("[bold magenta]Cloud: " + args.target + "[/bold magenta]")
        findings = cs.full_scan(args.target)
        if findings:
            t = Table(title="Cloud")
            t.add_column("Provider")
            t.add_column("Resource", style="cyan")
            t.add_column("Issue")
            t.add_column("Sev")
            for f in findings:
                t.add_row(f.provider, f.resource, f.issue, f.severity)
            console.print(t)
        else:
            console.print("[green]Clean[/green]")
        return
    if args.api and args.target:
        from .modules.api import APIDiscoverer
        ad = APIDiscoverer()
        console.print("[bold magenta]API: " + args.target + "[/bold magenta]")
        results = ad.scan(args.target)
        if results:
            t = Table(title="Endpoints")
            t.add_column("Path", style="cyan")
            t.add_column("Status")
            t.add_column("Reason")
            for r in results:
                t.add_row(r.path, str(r.status), r.reason or "-")
            console.print(t)
        else:
            console.print("[yellow]No endpoints[/yellow]")
        return
    if args.forward:
        from .modules.forward import PortForwarder
        pf = PortForwarder()
        parts = args.forward.split(":")
        if len(parts) == 3:
            rule = pf.add(int(parts[0]), parts[1], int(parts[2]))
            pf.start(rule)
            console.print("[green]Forwarding 127.0.0.1:" + parts[0] + " -> " + parts[1] + ":" + parts[2] + "[/green]")
            import time
            try:
                while True: time.sleep(1)
            except KeyboardInterrupt:
                pf.stop_all()
        else:
            console.print("[red]Format: LOCAL:REMOTE:PORT[/red]")
        return
    if args.export_csv or args.export_xml:
        from .modules.export import Exporter
        from .modules.history import HistoryDB
        exp = Exporter(args.output)
        db = HistoryDB()
        h = db.get_history(limit=1)
        if h:
            last = h[0]
            if args.export_csv:
                console.print("[green]CSV: " + exp.to_csv([last], last["target"]) + "[/green]")
            if args.export_xml:
                console.print("[green]XML: " + exp.to_xml(last, last["target"]) + "[/green]")
        else:
            console.print("[yellow]No history[/yellow]")
        db.close()
        return
    if args.schedule:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        parts = args.schedule.split()
        if parts:
            console.print("[green]" + sch.add_scan(parts[0], parts[1] if len(parts)>1 else "daily") + "[/green]")
        return
    if args.unschedule:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        console.print("[green]" + sch.remove_scan(args.unschedule) + "[/green]")
        return
    if args.list_schedules:
        from .modules.scheduler import Scheduler
        sch = Scheduler()
        entries = sch.list()
        if entries:
            for e in entries: console.print("  " + e)
        else:
            console.print("[yellow]No schedules[/yellow]")
        return
    if args.update:
        from .modules.update import Updater
        up = Updater()
        result = up.check()
        console.print("  Current: " + result["current"])
        console.print("  Latest:  " + result["latest"])
        console.print("  " + result["message"])
        return
    if args.logs:
        from .modules.logging_mod import B1pwerLogger
        logger = B1pwerLogger()
        entries = logger.tail(20)
        if entries:
            t = Table(title="Logs")
            t.add_column("Time")
            t.add_column("Level")
            t.add_column("Module")
            t.add_column("Msg")
            for e in entries:
                t.add_row(e["time"][:19], e["level"], e["module"], e["message"][:50])
            console.print(t)
        else:
            console.print("[yellow]No logs[/yellow]")
        return

    if not args.target:
        from .ui.app import B1pwerApp
        B1pwerApp().run()
        return

    if args.wifi:
        from .modules.wifi import WiFiScanner
        wf = WiFiScanner()
        if not wf.wlan:
            console.print("[red]No WiFi[/red]")
            return
        console.print("[bold magenta]WiFi: " + wf.wlan + "[/bold magenta]")
        nets = wf.scan()
        if nets:
            t = Table(title="WiFi")
            t.add_column("SSID", style="cyan")
            t.add_column("BSSID")
            t.add_column("Ch")
            t.add_column("Signal")
            for n in nets:
                t.add_row(n.ssid, n.bssid, str(n.channel), str(n.signal) + "dBm")
            console.print(t)
        return
    if args.udp:
        from .modules.udp import UDPScanner
        us = UDPScanner()
        console.print("[bold magenta]UDP: " + args.target + "[/bold magenta]")
        results = us.scan(args.target)
        open_ports = [r for r in results if r.state in ("open", "open|filtered")]
        t = Table(title="UDP (" + str(len(open_ports)) + ")")
        t.add_column("Port", style="yellow")
        t.add_column("State")
        t.add_column("Service")
        for r in open_ports:
            t.add_row(str(r.port), r.state, r.service or "-")
        console.print(t)
        return
    if args.subs:
        from .modules.subdomains import SubdomainScanner
        ss = SubdomainScanner()
        console.print("[bold magenta]Subs: " + args.target + "[/bold magenta]")
        subs = ss.scan(args.target)
        if subs:
            t = Table(title="Subs")
            t.add_column("Name", style="cyan")
            t.add_column("IP", style="yellow")
            for s in subs:
                t.add_row(s.name, s.ip or "-")
            console.print(t)
        return
    if args.ssl:
        from .modules.ssl import SSLScanner
        sa = SSLScanner()
        console.print("[bold magenta]SSL: " + args.target + "[/bold magenta]")
        result = sa.audit(args.target, args.ssl_port)
        t = Table(title="SSL")
        t.add_column("Item")
        t.add_column("Value")
        t.add_row("Protocol", result.protocol or "N/A")
        t.add_row("Key", str(result.key_size) + " bits")
        t.add_row("Days Left", str(result.days_remaining))
        t.add_row("SCORE", str(result.score) + "/100")
        console.print(t)
        return
    if args.nuclei:
        from .modules.nuclei import NucleiScanner
        nuclei = NucleiScanner()
        if not nuclei.available:
            console.print("[red]Nuclei not found[/red]")
            return
        console.print("[bold magenta]Nuclei: " + args.target + "[/bold magenta]")
        findings = nuclei.scan(args.target, severity=args.nuclei_severity, tags=args.nuclei_tags)
        if findings:
            t = Table(title="Findings (" + str(len(findings)) + ")")
            t.add_column("Sev")
            t.add_column("ID")
            t.add_column("Name")
            for f in findings:
                t.add_row(f.severity.upper(), f.cve or f.template_id[:25], f.name[:50])
            console.print(t)
        else:
            console.print("[green]Clean[/green]")
        return

    from .modules.scanner import B1pwerScanner
    from .modules.reporter import Reporter
    scanner = B1pwerScanner()
    reporter = Reporter(args.output)
    console.print("Scanning [bold]" + args.target + "[/bold] | " + args.profile)
    result = scanner.scan(args.target, args.profile)
    t = Table(title="Ports - " + result.target)
    t.add_column("Port", style="yellow")
    t.add_column("Proto")
    t.add_column("State", style="green")
    t.add_column("Service")
    t.add_column("Version")
    for p in result.ports:
        t.add_row(str(p.port), p.protocol, p.state, p.service, p.version)
    console.print(t)
    console.print("[green]" + str(len(result.ports)) + " open | " + str(len(result.vulnerabilities)) + " vulns | " + str(round(result.scan_duration,1)) + "s[/green]")

    if args.exploits and result.ports:
        from .modules.exploit import ExploitSuggester
        es = ExploitSuggester()
        suggestions = es.suggest(result.ports)
        if suggestions:
            console.print("[bold red]EXPLOITS (" + str(len(suggestions)) + "):[/bold red]")
            t2 = Table(title="Exploits")
            t2.add_column("Port")
            t2.add_column("CVE", style="red")
            t2.add_column("Sev")
            t2.add_column("MSF")
            for s in suggestions:
                t2.add_row(str(s.port), s.cve, s.severity, s.msf_module or "-")
            console.print(t2)

    paths = reporter.save_all(result)
    for fmt, path in paths.items():
        console.print("  " + fmt + ": " + path)

    from .modules.history import HistoryDB
    db = HistoryDB()
    db.save_scan(
        target=result.target, ip=result.ip, profile=args.profile,
        ports=[str(p.port) + "/" + p.protocol for p in result.ports],
        services=[(p.service + " " + p.version).strip() for p in result.ports],
        vulns=["[" + v["severity"] + "] " + v["script"] + ":" + str(v["port"]) for v in result.vulnerabilities],
        web_title=result.web_info.get("title", ""),
        duration=result.scan_duration
    )
    db.close()

if __name__ == "__main__":
    main()
