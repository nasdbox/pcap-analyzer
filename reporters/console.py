"""
reporters/console.py - Rich color console output using colorama + tabulate
"""

import sys
from colorama import Fore, Back, Style, init
from tabulate import tabulate

init(autoreset=True)

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}

RISK_COLORS = {
    "CRITICAL": Back.RED + Fore.WHITE + Style.BRIGHT,
    "HIGH": Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW": Fore.GREEN + Style.BRIGHT,
}


def _h1(text):
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'═' * 70}")
    print(f"  {text}")
    print(f"{'═' * 70}{Style.RESET_ALL}")


def _h2(text):
    print(f"\n{Fore.WHITE + Style.BRIGHT}  ▶  {text}{Style.RESET_ALL}")
    print(f"  {'─' * 50}")


def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


def _fmt_bps(bps):
    if bps < 1000:
        return f"{bps:.0f} bps"
    elif bps < 1_000_000:
        return f"{bps / 1000:.1f} Kbps"
    return f"{bps / 1_000_000:.2f} Mbps"


class ConsoleReporter:
    def __init__(self, results: dict):
        self.results = results

    def render(self, output_file=None):
        file = sys.stdout

        _h1("PacketLens Analysis Report")
        print(f"  File    : {self.results.get('file', 'N/A')}")
        print(f"  Packets : {self.results.get('packet_count', 0):,}")

        modules = self.results.get("modules", {})

        if "traffic" in modules:
            self._render_traffic(modules["traffic"])
        if "security" in modules:
            self._render_security(modules["security"])
        if "dns" in modules:
            self._render_dns(modules["dns"])
        if "http" in modules:
            self._render_http(modules["http"])
        if "sessions" in modules:
            self._render_sessions(modules["sessions"])

        print(f"\n{Fore.GREEN}  Analysis complete{Style.RESET_ALL}\n")


    def _render_traffic(self, data):
        _h1("TRAFFIC ANALYSIS")

        s = data.get("summary", {})
        _h2("Summary")
        rows = [
            ["Total Packets", f"{s.get('total_packets', 0):,}"],
            ["Total Bytes", _fmt_bytes(s.get("total_bytes", 0))],
            ["Duration", f"{s.get('duration_seconds', 0):.3f}s"],
            ["Throughput", _fmt_bps(s.get("throughput_bps", 0))],
            ["Avg Packet Size", f"{s.get('avg_packet_size', 0):.1f} B"],
            ["Min / Max Size", f"{s.get('min_packet_size', 0)} / {s.get('max_packet_size', 0)} B"],
        ]
        print(tabulate(rows, tablefmt="simple", colalign=("left", "right")))

        _h2("Protocol Distribution")
        proto = data.get("protocols", {})
        total = sum(proto.values()) or 1
        rows = [[p, f"{c:,}", f"{c/total*100:.1f}%"] for p, c in sorted(proto.items(), key=lambda x: -x[1])]
        print(tabulate(rows, headers=["Protocol", "Packets", "Share"], tablefmt="simple"))

        _h2("Packet Size Distribution")
        sdist = data.get("size_distribution", {})
        rows = [[k, f"{v:,}"] for k, v in sdist.items()]
        print(tabulate(rows, headers=["Bucket", "Count"], tablefmt="simple"))

        _h2("Top Source IPs (by bytes)")
        rows = [[
            Fore.YELLOW + e["ip"] + Style.RESET_ALL,
            _fmt_bytes(e["bytes"]),
            f"{e['packets']:,}",
        ] for e in data.get("top_sources", [])]
        print(tabulate(rows, headers=["Source IP", "Bytes", "Packets"], tablefmt="simple"))

        _h2("Top Destination IPs (by bytes)")
        rows = [[
            Fore.CYAN + e["ip"] + Style.RESET_ALL,
            _fmt_bytes(e["bytes"]),
            f"{e['packets']:,}",
        ] for e in data.get("top_destinations", [])]
        print(tabulate(rows, headers=["Destination IP", "Bytes", "Packets"], tablefmt="simple"))

        _h2("Top Ports")
        rows = [[e["port"], e["service"], f"{e['count']:,}"] for e in data.get("top_ports", [])]
        print(tabulate(rows, headers=["Port", "Service", "Count"], tablefmt="simple"))

        if data.get("ttl_distribution"):
            _h2("TTL Distribution (OS Fingerprinting)")
            rows = [[e["ttl"], e["count"], e["os_hint"]] for e in data["ttl_distribution"]]
            print(tabulate(rows, headers=["TTL", "Count", "OS Hint"], tablefmt="simple"))

    def _render_security(self, data):
        _h1("SECURITY ANALYSIS")

        risk = data.get("risk_level", "UNKNOWN")
        score = data.get("risk_score", 0)
        color = RISK_COLORS.get(risk, "")
        print(f"\n  Risk Level : {color}{risk}{Style.RESET_ALL}  (score: {score})")

        alerts = data.get("alerts", [])
        if alerts:
            _h2("Alerts")
            for a in alerts:
                color = SEVERITY_COLORS.get(a["severity"], "")
                print(f"  [{color}{a['severity']:8}{Style.RESET_ALL}] {a['type']}: {a['detail']}")

        findings = data.get("findings", [])
        if findings:
            _h2("Findings")
            rows = []
            for f in findings[:30]:
                color = SEVERITY_COLORS.get(f.get("severity", "INFO"), "")
                rows.append([
                    color + f.get("severity", "INFO") + Style.RESET_ALL,
                    f.get("type", ""),
                    f.get("src", ""),
                    f.get("dst", ""),
                    f.get("detail", "")[:60],
                ])
            print(tabulate(rows, headers=["Severity", "Type", "Src", "Dst", "Detail"], tablefmt="simple"))
        else:
            print(f"  {Fore.GREEN}  No security findings detected{Style.RESET_ALL}")

    def _render_dns(self, data):
        _h1("DNS ANALYSIS")

        print(f"  Total Queries  : {data.get('total_queries', 0):,}")
        print(f"  Unique Domains : {data.get('unique_domains', 0):,}")
        print(f"  NXDOMAIN       : {data.get('nxdomain_count', 0):,}")
        tunnel = data.get("tunneling_risk", False)
        t_color = Fore.RED if tunnel else Fore.GREEN
        print(f"  Tunnel Risk    : {t_color}{'YES' if tunnel else 'NO'}{Style.RESET_ALL}")

        _h2("Query Type Distribution")
        rows = [[k, v] for k, v in data.get("query_type_dist", {}).items()]
        print(tabulate(rows, headers=["Type", "Count"], tablefmt="simple"))

        _h2("Top Queried Domains")
        rows = [[e["domain"], e["count"]] for e in data.get("top_queried_domains", [])[:15]]
        print(tabulate(rows, headers=["Domain", "Count"], tablefmt="simple"))

        if data.get("suspicious_domains"):
            _h2("Suspicious Domains")
            rows = [[Fore.RED + e["domain"] + Style.RESET_ALL, e["reason"], e.get("src", "")] for e in data["suspicious_domains"]]
            print(tabulate(rows, headers=["Domain", "Reason", "Queried From"], tablefmt="simple"))

        if data.get("top_nxdomains"):
            _h2("Top NXDOMAIN Queries")
            rows = [[e["domain"], e["count"]] for e in data["top_nxdomains"]]
            print(tabulate(rows, headers=["Domain", "Count"], tablefmt="simple"))

    def _render_http(self, data):
        _h1("HTTP ANALYSIS")

        print(f"  Requests  : {data.get('total_requests', 0):,}")
        print(f"  Responses : {data.get('total_responses', 0):,}")

        _h2("HTTP Methods")
        rows = [[k, v] for k, v in data.get("method_distribution", {}).items()]
        print(tabulate(rows, headers=["Method", "Count"], tablefmt="simple"))

        _h2("Status Codes")
        rows = [[k, v] for k, v in sorted(data.get("status_code_distribution", {}).items())]
        print(tabulate(rows, headers=["Status", "Count"], tablefmt="simple"))

        _h2("Top Hosts")
        rows = [[e["host"], e["requests"]] for e in data.get("top_hosts", [])]
        print(tabulate(rows, headers=["Host", "Requests"], tablefmt="simple"))

        _h2("Top User Agents")
        rows = [[e["ua"][:70], e["count"]] for e in data.get("top_user_agents", [])]
        print(tabulate(rows, headers=["User-Agent", "Count"], tablefmt="simple"))

        if data.get("suspicious_requests"):
            _h2("Suspicious Requests")
            for r in data["suspicious_requests"][:10]:
                print(f"  [{r['src']}] {r['reason']}")
                print(f"       {r.get('host','')}{r.get('path','')[:80]}")

        if data.get("sensitive_headers"):
            _h2("Sensitive Headers Observed")
            rows = [[h["header"], h["src"], h["host"], h["value_preview"]] for h in data["sensitive_headers"]]
            print(tabulate(rows, headers=["Header", "From", "Host", "Value Preview"], tablefmt="simple"))

    def _render_sessions(self, data):
        _h1("SESSION ANALYSIS")

        print(f"  Total Sessions     : {data.get('total_sessions', 0):,}")
        print(f"  TCP Sessions       : {data.get('tcp_sessions', 0):,}")
        print(f"  UDP Sessions       : {data.get('udp_sessions', 0):,}")
        print(f"  Complete Handshakes: {data.get('complete_handshakes', 0):,}")

        _h2("Top Sessions (by bytes)")
        rows = [
            [s["proto"], s["src"], s["dst"], s["packets"], _fmt_bytes(s["bytes"]), s.get("flags", "-")]
            for s in data.get("sessions", [])[:20]
        ]
        print(tabulate(rows, headers=["Proto", "Src", "Dst", "Pkts", "Bytes", "Flags"], tablefmt="simple"))
