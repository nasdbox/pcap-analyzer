"""
utils/pcap_generator.py - Generate realistic synthetic PCAP files for testing
"""

import random
import time
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw,
    wrpcap, RandIP, RandMAC,
)

HTTP_HOSTS = ["example.com", "api.github.com", "cdn.jquery.com", "fonts.googleapis.com",
              "accounts.google.com", "login.microsoftonline.com", "s3.amazonaws.com"]
DNS_DOMAINS = ["google.com", "github.com", "stackoverflow.com", "amazon.com",
               "cloudflare.com", "reddit.com", "youtube.com", "twitter.com",
               "xn--p1b6ci4b4b3a.ru", "s3rv1ce-upd4te.tk",  # suspicious
               "aHR0cHM6Ly9leGFtcGxlLmNvbS9tYWxpY2lvdXM.evil.com"]  # base64 DNS tunnel sim
HTTP_PATHS = ["/", "/index.html", "/api/v1/users", "/login", "/static/main.js",
              "/search?q=test", "/admin", "/?id=1 UNION SELECT 1,2,3--"]
UA_STRINGS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/537.36",
    "python-requests/2.31.0",
    "sqlmap/1.7 (https://sqlmap.org)",  # suspicious
    "curl/7.88.1",
]

LOCAL_IPS = [f"192.168.1.{i}" for i in range(2, 20)] + ["10.0.0.5", "10.0.0.10"]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "104.21.0.1", "172.217.14.100",
                "185.220.101.34",  # known Tor exit
                "91.108.4.1"]


def _ts(base, offset):
    return base + offset


def generate_sample_pcap(output_path: str, count: int = 200):
    packets = []
    base_ts = time.time() - 120  # start 2 min ago
    offset = 0.0

    src_mac = "aa:bb:cc:dd:ee:01"
    gw_mac = "aa:bb:cc:dd:ee:02"

    def ts():
        nonlocal offset
        offset += random.uniform(0.001, 0.2)
        return base_ts + offset

    for domain in random.choices(DNS_DOMAINS, k=min(30, count // 5)):
        src_ip = random.choice(LOCAL_IPS)
        pkt = (
            Ether(src=src_mac, dst=gw_mac)
            / IP(src=src_ip, dst="8.8.8.8", ttl=64)
            / UDP(sport=random.randint(40000, 60000), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        pkt.time = ts()
        packets.append(pkt)

        resp = (
            Ether(src=gw_mac, dst=src_mac)
            / IP(src="8.8.8.8", dst=src_ip, ttl=55)
            / UDP(sport=53, dport=pkt[UDP].sport)
            / DNS(qr=1, aa=1, qd=DNSQR(qname=domain),
                  an=DNSRR(rrname=domain, type="A", rdata=random.choice(EXTERNAL_IPS), ttl=300))
        )
        resp.time = ts()
        packets.append(resp)

    for _ in range(min(40, count // 5)):
        src_ip = random.choice(LOCAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        host = random.choice(HTTP_HOSTS)
        path = random.choice(HTTP_PATHS)
        ua = random.choice(UA_STRINGS)
        method = random.choice(["GET", "GET", "GET", "POST"])
        sport = random.randint(40000, 60000)

        syn = Ether(src=src_mac, dst=gw_mac) / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=80, flags="S", seq=1000)
        syn.time = ts()
        packets.append(syn)

        synack = Ether(src=gw_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip, ttl=50) / TCP(sport=80, dport=sport, flags="SA", seq=2000, ack=1001)
        synack.time = ts()
        packets.append(synack)

        body = f"&username=admin&password=secret123" if method == "POST" else ""
        payload = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n{body}"
        ).encode()
        req = Ether(src=src_mac, dst=gw_mac) / IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(sport=sport, dport=80, flags="PA", seq=1001) / Raw(load=payload)
        req.time = ts()
        packets.append(req)

        status = random.choice(["200 OK", "200 OK", "200 OK", "301 Moved", "404 Not Found", "500 Internal Server Error"])
        resp_payload = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: 1234\r\n"
            f"Server: nginx/1.24\r\n"
            f"\r\n"
            + "<html><body>Hello World</body></html>" * 10
        ).encode()
        resp = Ether(src=gw_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip, ttl=50) / TCP(sport=80, dport=sport, flags="PA", seq=2001) / Raw(load=resp_payload)
        resp.time = ts()
        packets.append(resp)

    for _ in range(min(20, count // 10)):
        src_ip = random.choice(LOCAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        ping = Ether(src=src_mac, dst=gw_mac) / IP(src=src_ip, dst=dst_ip, ttl=64) / ICMP(type=8, id=1, seq=1) / Raw(b"x" * 56)
        ping.time = ts()
        packets.append(ping)
        pong = Ether(src=gw_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip, ttl=55) / ICMP(type=0, id=1, seq=1) / Raw(b"x" * 56)
        pong.time = ts()
        packets.append(pong)

    scanner_ip = "10.0.0.99"
    target_ip = "192.168.1.2"
    scan_ports = random.sample(range(1, 65535), 25)
    for port in scan_ports:
        syn = Ether(src=src_mac, dst=gw_mac) / IP(src=scanner_ip, dst=target_ip, ttl=64) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S")
        syn.time = ts()
        packets.append(syn)
        if random.random() > 0.5:
            rst = Ether(src=gw_mac, dst=src_mac) / IP(src=target_ip, dst=scanner_ip, ttl=64) / TCP(sport=port, dport=syn[TCP].sport, flags="RA")
            rst.time = ts()
            packets.append(rst)

    for _ in range(3):
        null_pkt = Ether(src=src_mac, dst=gw_mac) / IP(src="172.16.0.1", dst=target_ip, ttl=64) / TCP(dport=random.randint(1, 1024), flags=0x00)
        null_pkt.time = ts()
        packets.append(null_pkt)
    xmas_pkt = Ether(src=src_mac, dst=gw_mac) / IP(src="172.16.0.2", dst=target_ip, ttl=64) / TCP(dport=80, flags=0x29)
    xmas_pkt.time = ts()
    packets.append(xmas_pkt)

    ftp_src = random.choice(LOCAL_IPS)
    ftp_sport = random.randint(40000, 60000)
    ftp_req = Ether(src=src_mac, dst=gw_mac) / IP(src=ftp_src, dst="203.0.113.10", ttl=64) / TCP(sport=ftp_sport, dport=21, flags="PA") / Raw(b"USER admin\r\n")
    ftp_req.time = ts()
    packets.append(ftp_req)
    ftp_pass = Ether(src=src_mac, dst=gw_mac) / IP(src=ftp_src, dst="203.0.113.10", ttl=64) / TCP(sport=ftp_sport, dport=21, flags="PA") / Raw(b"PASS hunter2\r\n")
    ftp_pass.time = ts()
    packets.append(ftp_pass)

    big_src = random.choice(LOCAL_IPS)
    big_dst = random.choice(EXTERNAL_IPS)
    big_sport = random.randint(40000, 60000)
    for i in range(15):
        chunk = Ether(src=src_mac, dst=gw_mac) / IP(src=big_src, dst=big_dst, ttl=64) / TCP(sport=big_sport, dport=443, flags="PA", seq=i * 1400) / Raw(b"X" * 1400)
        chunk.time = ts()
        packets.append(chunk)

    for _ in range(5):
        arp = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=random.choice(LOCAL_IPS))
        arp.time = ts()
        packets.append(arp)

    random.shuffle(packets)
    packets.sort(key=lambda p: float(p.time) if hasattr(p, "time") else 0)

    wrpcap(output_path, packets)
    print(f"  Generated {len(packets)} packets → {output_path}")
