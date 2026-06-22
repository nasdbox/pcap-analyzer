"""
analyzers/traffic.py - Protocol breakdown, top talkers, bandwidth, packet stats
"""

from collections import Counter, defaultdict
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether, PacketList
from utils.logger import setup_logger

logger = setup_logger(__name__)

PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 162: "SNMP-trap", 179: "BGP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 6881: "BitTorrent", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "Jupyter", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def port_to_service(port: int) -> str:
    return PORT_SERVICES.get(port, str(port))


class TrafficAnalyzer:
    """High-level traffic statistics and protocol breakdown."""

    def __init__(self, packets: PacketList, top_n: int = 10):
        self.packets = packets
        self.top_n = top_n

    def analyze(self) -> dict:
        proto_counter = Counter()
        src_ip_bytes = defaultdict(int)
        dst_ip_bytes = defaultdict(int)
        src_ip_pkts = Counter()
        dst_ip_pkts = Counter()
        port_counter = Counter()
        sizes = []
        timestamps = []
        eth_types = Counter()
        tcp_flags_dist = Counter()
        ttl_dist = Counter()

        for pkt in self.packets:
            size = len(pkt)
            sizes.append(size)

            if hasattr(pkt, "time"):
                timestamps.append(float(pkt.time))

            if pkt.haslayer(Ether):
                eth_types[pkt[Ether].type] += 1

            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                ttl = pkt[IP].ttl
                ttl_dist[ttl] += 1
                src_ip_bytes[src] += size
                dst_ip_bytes[dst] += size
                src_ip_pkts[src] += 1
                dst_ip_pkts[dst] += 1

            elif pkt.haslayer(IPv6):
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                src_ip_bytes[src] += size
                dst_ip_bytes[dst] += size
                src_ip_pkts[src] += 1
                dst_ip_pkts[dst] += 1

            if pkt.haslayer(TCP):
                proto_counter["TCP"] += 1
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                port_counter[sport] += 1
                port_counter[dport] += 1
                flags = pkt[TCP].flags
                flag_str = self._flags_str(flags)
                tcp_flags_dist[flag_str] += 1

            elif pkt.haslayer(UDP):
                proto_counter["UDP"] += 1
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                port_counter[sport] += 1
                port_counter[dport] += 1

            elif pkt.haslayer(ICMP):
                proto_counter["ICMP"] += 1
            elif pkt.haslayer(ARP):
                proto_counter["ARP"] += 1
            elif pkt.haslayer(IPv6):
                proto_counter["IPv6"] += 1
            else:
                proto_counter["Other"] += 1

        total_pkts = len(self.packets)
        total_bytes = sum(sizes)

        duration = 0.0
        throughput_bps = 0.0
        if len(timestamps) > 1:
            duration = max(timestamps) - min(timestamps)
            if duration > 0:
                throughput_bps = (total_bytes * 8) / duration

        size_buckets = {"tiny(<64)": 0, "small(64-256)": 0, "medium(256-1024)": 0, "large(>1024)": 0}
        for s in sizes:
            if s < 64:
                size_buckets["tiny(<64)"] += 1
            elif s < 256:
                size_buckets["small(64-256)"] += 1
            elif s < 1024:
                size_buckets["medium(256-1024)"] += 1
            else:
                size_buckets["large(>1024)"] += 1

        top_src_bytes = [
            {"ip": ip, "bytes": b, "packets": src_ip_pkts[ip]}
            for ip, b in sorted(src_ip_bytes.items(), key=lambda x: -x[1])[: self.top_n]
        ]
        top_dst_bytes = [
            {"ip": ip, "bytes": b, "packets": dst_ip_pkts[ip]}
            for ip, b in sorted(dst_ip_bytes.items(), key=lambda x: -x[1])[: self.top_n]
        ]

        top_ports = [
            {"port": port, "service": port_to_service(port), "count": cnt}
            for port, cnt in port_counter.most_common(self.top_n)
        ]

        ttl_hints = []
        for ttl, cnt in sorted(ttl_dist.items(), key=lambda x: -x[1])[:5]:
            os_hint = _ttl_os_hint(ttl)
            ttl_hints.append({"ttl": ttl, "count": cnt, "os_hint": os_hint})

        return {
            "summary": {
                "total_packets": total_pkts,
                "total_bytes": total_bytes,
                "duration_seconds": round(duration, 3),
                "throughput_bps": round(throughput_bps, 1),
                "avg_packet_size": round(total_bytes / total_pkts, 1) if total_pkts else 0,
                "min_packet_size": min(sizes) if sizes else 0,
                "max_packet_size": max(sizes) if sizes else 0,
            },
            "protocols": dict(proto_counter),
            "size_distribution": size_buckets,
            "top_sources": top_src_bytes,
            "top_destinations": top_dst_bytes,
            "top_ports": top_ports,
            "tcp_flags": dict(tcp_flags_dist.most_common(10)),
            "ttl_distribution": ttl_hints,
        }

    def _flags_str(self, flags) -> str:
        parts = []
        if flags & 0x02:
            parts.append("SYN")
        if flags & 0x10:
            parts.append("ACK")
        if flags & 0x01:
            parts.append("FIN")
        if flags & 0x04:
            parts.append("RST")
        if flags & 0x08:
            parts.append("PSH")
        if flags & 0x20:
            parts.append("URG")
        return "+".join(parts) if parts else "NONE"


def _ttl_os_hint(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/macOS (TTL≤64)"
    elif ttl <= 128:
        return "Windows (TTL≤128)"
    elif ttl <= 255:
        return "Cisco/Network device"
    return "Unknown"
