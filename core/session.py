"""
core/session.py - TCP/UDP session reconstruction and flow tracking
"""

from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, PacketList
from utils.logger import setup_logger

logger = setup_logger(__name__)


class SessionManager:
    """
    Reconstructs network sessions (flows) from packets.
    A session is identified by the 5-tuple: proto, src_ip, src_port, dst_ip, dst_port
    """

    def __init__(self, packets: PacketList):
        self.packets = packets
        self.sessions = defaultdict(list)

    def _flow_key(self, packet):
        """Return a canonical (sorted) flow key for a packet."""
        proto = None
        src_ip = dst_ip = "?"
        sport = dport = 0

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return None

        if (src_ip, sport) < (dst_ip, dport):
            return (proto, src_ip, sport, dst_ip, dport)
        else:
            return (proto, dst_ip, dport, src_ip, sport)

    def build_sessions(self):
        for pkt in self.packets:
            key = self._flow_key(pkt)
            if key:
                self.sessions[key].append(pkt)
        return self.sessions

    def analyze(self) -> dict:
        self.build_sessions()

        session_list = []
        for key, pkts in self.sessions.items():
            proto, ip_a, port_a, ip_b, port_b = key
            total_bytes = sum(len(p) for p in pkts)

            flags_seen = set()
            if proto == "TCP":
                for p in pkts:
                    if p.haslayer(TCP):
                        f = p[TCP].flags
                        if f & 0x02:
                            flags_seen.add("SYN")
                        if f & 0x10:
                            flags_seen.add("ACK")
                        if f & 0x01:
                            flags_seen.add("FIN")
                        if f & 0x04:
                            flags_seen.add("RST")
                        if f & 0x08:
                            flags_seen.add("PSH")

            handshake = "SYN" in flags_seen and "ACK" in flags_seen
            closed = "FIN" in flags_seen or "RST" in flags_seen

            session_list.append({
                "proto": proto,
                "src": f"{ip_a}:{port_a}",
                "dst": f"{ip_b}:{port_b}",
                "packets": len(pkts),
                "bytes": total_bytes,
                "flags": ",".join(sorted(flags_seen)) if flags_seen else "-",
                "handshake": handshake,
                "closed": closed,
            })

        session_list.sort(key=lambda x: x["bytes"], reverse=True)

        return {
            "total_sessions": len(session_list),
            "tcp_sessions": sum(1 for s in session_list if s["proto"] == "TCP"),
            "udp_sessions": sum(1 for s in session_list if s["proto"] == "UDP"),
            "complete_handshakes": sum(1 for s in session_list if s.get("handshake")),
            "sessions": session_list[:50],  # cap at 50 for reporting
        }
