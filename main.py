#!/usr/bin/env python3
"""
PacketLens - Packet Capture Analysis Tool
A full-featured network traffic analyzer built with Scapy.
"""

import argparse
import sys
import os
from pathlib import Path

from core.capture import PacketCapture
from core.session import SessionManager
from analyzers.traffic import TrafficAnalyzer
from analyzers.security import SecurityAnalyzer
from analyzers.dns import DNSAnalyzer
from analyzers.http import HTTPAnalyzer
from reporters.console import ConsoleReporter
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from utils.logger import setup_logger
from utils.pcap_generator import generate_sample_pcap

logger = setup_logger(__name__)

BANNER = r"""
  ____            _        _   _     
 |  _ \ __ _  __| | _____| |_| |    ___ _ __  ___ 
 | |_) / _` |/ _` |/ / _ \ __| |   / _ \ '_ \/ __|
 |  __/ (_| | (_| |   <  __/ |_| |__|  __/ | | \__ \
 |_|   \__,_|\__,_|_|\_\___|\__|_____\___|_| |_|___/
 
 Network Packet Capture & Analysis Tool  v1.0.0
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="packetlens",
        description="PacketLens - Advanced Packet Capture Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze a PCAP file:
    python main.py analyze -f capture.pcap

  Analyze with all modules:
    python main.py analyze -f capture.pcap --all

  Generate a sample PCAP for testing:
    python main.py sample --output test.pcap

  Live capture (requires root):
    python main.py capture --interface eth0 --count 100

  Export report:
    python main.py analyze -f capture.pcap --report html --output report.html
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a PCAP file")
    analyze_parser.add_argument("-f", "--file", required=True, help="Path to PCAP file")
    analyze_parser.add_argument("--traffic", action="store_true", help="Run traffic analysis")
    analyze_parser.add_argument("--security", action="store_true", help="Run security analysis")
    analyze_parser.add_argument("--dns", action="store_true", help="Run DNS analysis")
    analyze_parser.add_argument("--http", action="store_true", help="Run HTTP analysis")
    analyze_parser.add_argument("--sessions", action="store_true", help="Show TCP/UDP sessions")
    analyze_parser.add_argument("--all", action="store_true", help="Run all analysis modules")
    analyze_parser.add_argument("--top", type=int, default=10, metavar="N", help="Show top N entries (default: 10)")
    analyze_parser.add_argument("--filter", metavar="BPF", help="BPF filter to apply (e.g. 'tcp port 80')")
    analyze_parser.add_argument("--report", choices=["console", "json", "html"], default="console", help="Output report format")
    analyze_parser.add_argument("--output", metavar="FILE", help="Output file for report (json/html)")

    cap_parser = subparsers.add_parser("capture", help="Live packet capture (requires root/admin)")
    cap_parser.add_argument("--interface", "-i", default=None, help="Network interface (default: auto-detect)")
    cap_parser.add_argument("--count", "-c", type=int, default=50, help="Number of packets to capture (default: 50)")
    cap_parser.add_argument("--filter", metavar="BPF", help="BPF filter")
    cap_parser.add_argument("--output", "-o", metavar="FILE", help="Save capture to PCAP file")
    cap_parser.add_argument("--timeout", type=int, default=30, help="Capture timeout in seconds (default: 30)")

    sample_parser = subparsers.add_parser("sample", help="Generate a synthetic PCAP for testing")
    sample_parser.add_argument("--output", "-o", default="sample_capture.pcap", help="Output PCAP path")
    sample_parser.add_argument("--packets", type=int, default=200, help="Number of packets to generate (default: 200)")

    subparsers.add_parser("info", help="Show available network interfaces")

    return parser


def cmd_analyze(args):
    path = Path(args.file)
    if not path.exists():
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    print(f"\nLoading: {path.name} ({path.stat().st_size / 1024:.1f} KB)\n")

    capture = PacketCapture()
    packets = capture.load_pcap(str(path), bpf_filter=args.filter)

    if not packets:
        print("No packets loaded (empty file or filter matched nothing).")
        sys.exit(0)

    run_all = args.all
    results = {"file": str(path), "packet_count": len(packets), "modules": {}}

    if run_all or args.traffic:
        ta = TrafficAnalyzer(packets, top_n=args.top)
        results["modules"]["traffic"] = ta.analyze()

    if run_all or args.security:
        sa = SecurityAnalyzer(packets)
        results["modules"]["security"] = sa.analyze()

    if run_all or args.dns:
        da = DNSAnalyzer(packets)
        results["modules"]["dns"] = da.analyze()

    if run_all or args.http:
        ha = HTTPAnalyzer(packets)
        results["modules"]["http"] = ha.analyze()

    if run_all or args.sessions:
        sm = SessionManager(packets)
        results["modules"]["sessions"] = sm.analyze()

    if not results["modules"]:
        ta = TrafficAnalyzer(packets, top_n=args.top)
        results["modules"]["traffic"] = ta.analyze()

    if args.report == "json":
        reporter = JSONReporter(results)
        reporter.render(output_file=args.output)
    elif args.report == "html":
        reporter = HTMLReporter(results)
        reporter.render(output_file=args.output)
    else:
        reporter = ConsoleReporter(results)
        reporter.render()


def cmd_capture(args):
    print("\nStarting live capture...\n")
    capture = PacketCapture()
    try:
        packets = capture.live_capture(
            iface=args.interface,
            count=args.count,
            bpf_filter=args.filter,
            timeout=args.timeout,
        )
        if args.output:
            capture.save_pcap(packets, args.output)
            print(f"\nSaved {len(packets)} packets to {args.output}")

        if packets:
            ta = TrafficAnalyzer(packets, top_n=5)
            results = {"file": "live_capture", "packet_count": len(packets), "modules": {"traffic": ta.analyze()}}
            ConsoleReporter(results).render()
    except PermissionError:
        print("Live capture requires root/administrator privileges.")
        print("   Try: sudo python main.py capture ...")
        sys.exit(1)


def cmd_sample(args):
    print(f"\nGenerating {args.packets} synthetic packets...")
    generate_sample_pcap(args.output, count=args.packets)
    print(f"Sample PCAP saved to: {args.output}")
    print(f"   Run: python main.py analyze -f {args.output} --all")


def cmd_info():
    from scapy.all import get_if_list, get_if_addr
    print("\nAvailable Network Interfaces:\n")
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "N/A"
        print(f"  {iface:<20} {addr}")
    print()


def main():
    print(BANNER)
    parser = parse_args()
    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "capture":
        cmd_capture(args)
    elif args.command == "sample":
        cmd_sample(args)
    elif args.command == "info":
        cmd_info()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
