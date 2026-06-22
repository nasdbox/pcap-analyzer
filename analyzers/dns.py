"""
analyzers/dns.py - DNS query/response analysis, tunneling detection, suspicious domains
"""

from collections import Counter, defaultdict
from scapy.all import DNS, DNSQR, DNSRR, UDP, TCP, IP, PacketList
from utils.logger import setup_logger
import re

logger = setup_logger(__name__)

DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}

SUSPICIOUS_TLDS = {".ru", ".cn", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"}


def _looks_like_dga(name: str) -> bool:
    """Heuristic: high consonant ratio + long label = DGA-generated domain."""
    parts = name.rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[-2]  # second-level domain
    if len(label) < 10:
        return False
    vowels = sum(1 for c in label if c in "aeiou")
    ratio = vowels / len(label)
    return ratio < 0.2  # very few vowels = suspicious


class DNSAnalyzer:
    def __init__(self, packets: PacketList):
        self.packets = packets

    def analyze(self) -> dict:
        query_counter = Counter()
        rtype_counter = Counter()
        nxdomain_counter = Counter()
        resolvers = Counter()
        txt_records = []
        suspicious_domains = []
        all_queries = []
        failed_lookups = []

        oversized_labels = []

        for pkt in self.packets:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]

            if pkt.haslayer(IP):
                dst = pkt[IP].dst
                src = pkt[IP].src

            if dns.qr == 0 and dns.qdcount > 0:  # query
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    qtype = DNS_QTYPES.get(dns.qd.qtype, str(dns.qd.qtype))
                    query_counter[qname] += 1
                    rtype_counter[qtype] += 1
                    resolvers[dst] += 1
                    all_queries.append({"name": qname, "type": qtype, "src": src})

                    if _looks_like_dga(qname):
                        suspicious_domains.append({
                            "domain": qname,
                            "reason": "DGA-like pattern (low vowel ratio)",
                            "src": src,
                        })

                    for label in qname.split("."):
                        if len(label) > 40:
                            oversized_labels.append({"label": label, "domain": qname, "src": src})

                    for tld in SUSPICIOUS_TLDS:
                        if qname.endswith(tld):
                            suspicious_domains.append({
                                "domain": qname,
                                "reason": f"Suspicious TLD ({tld})",
                                "src": src,
                            })
                except Exception:
                    pass

            elif dns.qr == 1:
                if dns.rcode == 3 and dns.qdcount > 0:
                    try:
                        qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                        nxdomain_counter[qname] += 1
                        failed_lookups.append(qname)
                    except Exception:
                        pass

                if dns.ancount > 0:
                    try:
                        for i in range(dns.ancount):
                            rr = dns.an
                            for _ in range(i):
                                rr = rr.payload
                            if hasattr(rr, "type") and rr.type == 16:  # TXT
                                name = rr.rrname.decode("utf-8", errors="replace")
                                data = str(rr.rdata)
                                txt_records.append({"name": name, "data": data[:200]})
                    except Exception:
                        pass

        tunneling_risk = False
        if len(oversized_labels) > 5:
            tunneling_risk = True
        total_q = sum(query_counter.values())
        total_nx = sum(nxdomain_counter.values())
        if total_q > 20 and total_nx / max(total_q, 1) > 0.3:
            tunneling_risk = True

        return {
            "total_queries": total_q,
            "unique_domains": len(query_counter),
            "nxdomain_count": total_nx,
            "tunneling_risk": tunneling_risk,
            "query_type_dist": dict(rtype_counter.most_common(10)),
            "top_queried_domains": [
                {"domain": d, "count": c} for d, c in query_counter.most_common(20)
            ],
            "top_nxdomains": [
                {"domain": d, "count": c} for d, c in nxdomain_counter.most_common(10)
            ],
            "top_resolvers": [
                {"resolver": r, "queries": c} for r, c in resolvers.most_common(5)
            ],
            "txt_records": txt_records[:10],
            "suspicious_domains": suspicious_domains[:20],
            "oversized_labels": oversized_labels[:10],
        }
