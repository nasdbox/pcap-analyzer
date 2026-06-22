"""
core/capture.py - Packet loading, live capture, and PCAP I/O
"""

import os
from scapy.all import rdpcap, sniff, wrpcap, PacketList
from utils.logger import setup_logger

logger = setup_logger(__name__)


class PacketCapture:
    """Handles loading PCAP files and live capture via Scapy."""

    def load_pcap(self, path: str, bpf_filter: str = None) -> PacketList:
        """Load packets from a PCAP file, optionally applying a BPF filter."""
        logger.info(f"Loading PCAP: {path}")
        try:
            packets = rdpcap(path)
        except Exception as e:
            logger.error(f"Failed to read PCAP: {e}")
            return PacketList()

        if bpf_filter:
            try:
                packets = PacketList([p for p in packets if self._bpf_match(p, bpf_filter)])
                logger.info(f"BPF filter '{bpf_filter}' applied: {len(packets)} packets remaining")
            except Exception as e:
                logger.warning(f"BPF filter application failed: {e}")

        logger.info(f"Loaded {len(packets)} packets")
        return packets

    def live_capture(
        self,
        iface: str = None,
        count: int = 50,
        bpf_filter: str = None,
        timeout: int = 30,
    ) -> PacketList:
        """Capture packets live from a network interface."""
        kwargs = {"count": count, "timeout": timeout, "store": True}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        print(f"  Interface : {iface or 'auto'}")
        print(f"  Count     : {count} packets")
        print(f"  Filter    : {bpf_filter or 'none'}")
        print(f"  Timeout   : {timeout}s\n")

        captured = []

        def _on_packet(pkt):
            captured.append(pkt)
            print(f"\r  Captured: {len(captured)}/{count} packets", end="", flush=True)

        sniff(prn=_on_packet, **kwargs)
        print()
        return PacketList(captured)

    def save_pcap(self, packets: PacketList, path: str):
        """Write packets to a PCAP file."""
        wrpcap(path, packets)
        logger.info(f"Saved {len(packets)} packets to {path}")

    def _bpf_match(self, packet, bpf_filter: str) -> bool:
        """Very basic BPF emulation using Scapy layer names (subset only)."""
        f = bpf_filter.lower()
        from scapy.all import TCP, UDP, ICMP, IP, IPv6, ARP, DNS

        if "tcp" in f and not packet.haslayer(TCP):
            return False
        if "udp" in f and not packet.haslayer(UDP):
            return False
        if "icmp" in f and not packet.haslayer(ICMP):
            return False
        if "arp" in f and not packet.haslayer(ARP):
            return False
        if "dns" in f and not packet.haslayer(DNS):
            return False

        import re
        port_match = re.search(r"port\s+(\d+)", f)
        if port_match:
            port = int(port_match.group(1))
            if packet.haslayer(TCP):
                if packet[TCP].sport != port and packet[TCP].dport != port:
                    return False
            elif packet.haslayer(UDP):
                if packet[UDP].sport != port and packet[UDP].dport != port:
                    return False
            else:
                return False

        host_match = re.search(r"host\s+([\d\.]+)", f)
        if host_match:
            host = host_match.group(1)
            if packet.haslayer(IP):
                if packet[IP].src != host and packet[IP].dst != host:
                    return False
            else:
                return False

        return True
