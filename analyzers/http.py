"""
analyzers/http.py - HTTP request/response extraction and analysis
"""

from collections import Counter
from scapy.all import TCP, IP, Raw, PacketList
from utils.logger import setup_logger
import re

logger = setup_logger(__name__)

HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+(HTTP/[\d\.]+)\r\n(.*?)\r\n\r\n",
    re.DOTALL,
)
HTTP_RESPONSE_RE = re.compile(
    rb"^(HTTP/[\d\.]+)\s+(\d{3})\s+([^\r\n]*)\r\n(.*?)\r\n\r\n",
    re.DOTALL,
)
HEADER_RE = re.compile(rb"^([\w\-]+):\s*(.+)$", re.MULTILINE)

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
SUSPICIOUS_UAS = ["sqlmap", "nmap", "nikto", "masscan", "dirbuster", "hydra", "curl/7", "python-requests/0", "go-http"]


class HTTPAnalyzer:
    """Extract and analyze HTTP/1.x traffic from raw TCP payloads."""

    def __init__(self, packets: PacketList):
        self.packets = packets

    def analyze(self) -> dict:
        requests = []
        responses = []
        method_counter = Counter()
        status_counter = Counter()
        host_counter = Counter()
        ua_counter = Counter()
        suspicious_requests = []
        sensitive_headers_seen = []
        content_types = Counter()

        for pkt in self.packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
                continue
            payload = bytes(pkt[Raw].load)
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            req_match = HTTP_REQUEST_RE.match(payload)
            if req_match:
                method = req_match.group(1).decode("utf-8", errors="replace")
                path = req_match.group(2).decode("utf-8", errors="replace")
                version = req_match.group(3).decode("utf-8", errors="replace")
                header_block = req_match.group(4)
                headers = self._parse_headers(header_block)

                host = headers.get("host", dst)
                ua = headers.get("user-agent", "Unknown")
                ua_counter[ua[:80]] += 1
                host_counter[host] += 1
                method_counter[method] += 1

                entry = {
                    "method": method,
                    "host": host,
                    "path": path,
                    "version": version,
                    "src": src,
                    "dst": dst,
                    "user_agent": ua[:120],
                }
                requests.append(entry)

                for sus_ua in SUSPICIOUS_UAS:
                    if sus_ua.lower() in ua.lower():
                        suspicious_requests.append({
                            "reason": f"Suspicious User-Agent: {ua[:60]}",
                            "src": src,
                            "host": host,
                            "path": path,
                        })

                if re.search(r"(union\s+select|<script|%3cscript|1=1|'--|\bor\b\s+1)", path, re.IGNORECASE):
                    suspicious_requests.append({
                        "reason": "Possible injection in URL",
                        "src": src,
                        "host": host,
                        "path": path[:200],
                    })

                for h in SENSITIVE_HEADERS:
                    if h in headers:
                        sensitive_headers_seen.append({
                            "header": h,
                            "src": src,
                            "host": host,
                            "value_preview": headers[h][:40] + "...",
                        })

            res_match = HTTP_RESPONSE_RE.match(payload)
            if res_match:
                version = res_match.group(1).decode("utf-8", errors="replace")
                status = res_match.group(2).decode("utf-8", errors="replace")
                reason = res_match.group(3).decode("utf-8", errors="replace")
                header_block = res_match.group(4)
                headers = self._parse_headers(header_block)

                status_counter[int(status)] += 1
                ct = headers.get("content-type", "")
                if ct:
                    content_types[ct.split(";")[0].strip()] += 1

                responses.append({
                    "status": status,
                    "reason": reason,
                    "src": src,
                    "content_type": ct[:60],
                })

        status_classes = Counter()
        for code, cnt in status_counter.items():
            cls = f"{code // 100}xx"
            status_classes[cls] += cnt

        return {
            "total_requests": len(requests),
            "total_responses": len(responses),
            "method_distribution": dict(method_counter),
            "status_code_distribution": dict(status_counter.most_common(15)),
            "status_classes": dict(status_classes),
            "top_hosts": [{"host": h, "requests": c} for h, c in host_counter.most_common(10)],
            "top_user_agents": [{"ua": ua, "count": c} for ua, c in ua_counter.most_common(10)],
            "top_content_types": dict(content_types.most_common(10)),
            "suspicious_requests": suspicious_requests[:20],
            "sensitive_headers": sensitive_headers_seen[:10],
            "requests_sample": requests[:10],
        }

    def _parse_headers(self, header_block: bytes) -> dict:
        headers = {}
        for match in HEADER_RE.finditer(header_block):
            key = match.group(1).decode("utf-8", errors="replace").lower()
            val = match.group(2).decode("utf-8", errors="replace").strip()
            headers[key] = val
        return headers
