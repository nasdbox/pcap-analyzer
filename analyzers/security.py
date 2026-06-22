"""
analyzers/security.py - Security-focused analysis: port scans, suspicious traffic,
                         cleartext credentials, known malicious patterns.
"""

from collections import defaultdict, Counter
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Raw, PacketList
from utils.logger import setup_logger
import re

logger = setup_logger(__name__)

DANGEROUS_PORTS = {
    23: "Telnet (cleartext)", 21: "FTP (cleartext)",
    69: "TFTP", 161: "SNMP (community strings)",
    512: "rexec", 513: "rlogin", 514: "rsh",
    2323: "Telnet-alt", 4444: "Metasploit-default",
    5555: "Android ADB", 6666: "IRC (common malware)",
    6667: "IRC", 31337: "Back Orifice",
}

CREDENTIAL_PATTERNS = [
    (re.compile(rb"USER\s+(\S+)", re.IGNORECASE), "FTP USER"),
    (re.compile(rb"PASS\s+(\S+)", re.IGNORECASE), "FTP PASS"),
    (re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE), "HTTP Basic Auth"),
    (re.compile(rb"password[=:]\s*([^\s&\r\n]+)", re.IGNORECASE), "HTTP password param"),
    (re.compile(rb"passwd[=:]\s*([^\s&\r\n]+)", re.IGNORECASE), "HTTP passwd param"),
    (re.compile(rb"AUTH\s+LOGIN", re.IGNORECASE), "SMTP AUTH"),
]

SUSPICIOUS_UA = ["sqlmap", "nmap", "masscan", "nikto", "dirbuster", "hydra", "metasploit"]


class SecurityAnalyzer:
    """Detects suspicious and potentially malicious traffic patterns."""

    def __init__(self, packets: PacketList):
        self.packets = packets

    def analyze(self) -> dict:
        findings = []
        alerts = []

        scan_findings = self._detect_port_scans()
        findings.extend(scan_findings["details"])
        if scan_findings["scanners"]:
            alerts.append({
                "severity": "HIGH",
                "type": "Port Scan",
                "detail": f"{len(scan_findings['scanners'])} potential scanner(s) detected",
            })

        cleartext_findings = self._detect_cleartext_protocols()
        findings.extend(cleartext_findings)
        if cleartext_findings:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Cleartext Protocol",
                "detail": f"{len(cleartext_findings)} dangerous protocol instance(s) observed",
            })

        cred_findings = self._detect_credentials()
        if cred_findings:
            alerts.append({
                "severity": "CRITICAL",
                "type": "Cleartext Credentials",
                "detail": f"{len(cred_findings)} potential credential exposure(s)",
            })
            findings.extend(cred_findings)

        icmp_findings = self._detect_icmp_anomalies()
        if icmp_findings:
            alerts.append({
                "severity": "LOW",
                "type": "ICMP Anomaly",
                "detail": f"{len(icmp_findings)} ICMP anomaly(s)",
            })
            findings.extend(icmp_findings)

        flag_findings = self._detect_tcp_flag_anomalies()
        if flag_findings:
            alerts.append({
                "severity": "HIGH",
                "type": "TCP Flag Anomaly",
                "detail": f"{len(flag_findings)} anomalous TCP flag combination(s)",
            })
            findings.extend(flag_findings)

        exfil_findings = self._detect_large_transfers()
        if exfil_findings:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Large Data Transfer",
                "detail": f"{len(exfil_findings)} large flow(s) detected",
            })
            findings.extend(exfil_findings)

        risk_score = sum(
            {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}.get(a["severity"], 0)
            for a in alerts
        )
        risk_level = "LOW"
        if risk_score >= 60:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "alerts": alerts,
            "findings": findings[:100],  # cap for report size
        }


    def _detect_port_scans(self) -> dict:
        """Detect hosts that SYN-probe many distinct ports."""
        src_ports = defaultdict(set)
        src_syn_count = Counter()

        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                is_syn_only = (flags & 0x3F) == 0x02  # SYN, no ACK
                if is_syn_only:
                    src = pkt[IP].src
                    dst_port = pkt[TCP].dport
                    src_ports[src].add(dst_port)
                    src_syn_count[src] += 1

        scanners = []
        details = []
        threshold = 15  # distinct ports within the capture
        for src, ports in src_ports.items():
            if len(ports) >= threshold:
                scanners.append(src)
                details.append({
                    "type": "Port Scan",
                    "severity": "HIGH",
                    "src": src,
                    "detail": f"SYN probe to {len(ports)} distinct ports",
                    "ports_sample": sorted(list(ports))[:20],
                })

        return {"scanners": scanners, "details": details}

    def _detect_cleartext_protocols(self) -> list:
        findings = []
        seen = set()
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                for port in (dport, sport):
                    if port in DANGEROUS_PORTS and port not in seen:
                        seen.add(port)
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        findings.append({
                            "type": "Cleartext Protocol",
                            "severity": "MEDIUM",
                            "src": src,
                            "dst": dst,
                            "detail": f"Port {port}: {DANGEROUS_PORTS[port]}",
                        })
        return findings

    def _detect_credentials(self) -> list:
        findings = []
        for pkt in self.packets:
            if not pkt.haslayer(Raw):
                continue
            payload = bytes(pkt[Raw].load)
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            for pattern, label in CREDENTIAL_PATTERNS:
                match = pattern.search(payload)
                if match:
                    value = match.group(1)[:20].decode("utf-8", errors="replace")
                    redacted = value[:3] + "***" if len(value) > 3 else "***"
                    findings.append({
                        "type": "Cleartext Credential",
                        "severity": "CRITICAL",
                        "src": src,
                        "dst": dst,
                        "detail": f"{label} detected — value starts with: {redacted}",
                    })
        return findings

    def _detect_icmp_anomalies(self) -> list:
        findings = []
        large_icmp_threshold = 1000  # bytes
        for pkt in self.packets:
            if pkt.haslayer(ICMP):
                size = len(pkt)
                icmp_type = pkt[ICMP].type
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                if size > large_icmp_threshold:
                    findings.append({
                        "type": "Large ICMP",
                        "severity": "LOW",
                        "src": src,
                        "detail": f"ICMP type={icmp_type}, size={size} bytes (possible tunnel/exfil)",
                    })
        return findings[:20]

    def _detect_tcp_flag_anomalies(self) -> list:
        findings = []
        for pkt in self.packets:
            if not pkt.haslayer(TCP):
                continue
            flags = pkt[TCP].flags & 0x3F
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            dport = pkt[TCP].dport

            if flags == 0x00:
                findings.append({
                    "type": "NULL Scan",
                    "severity": "HIGH",
                    "src": src,
                    "dst": f"{dst}:{dport}",
                    "detail": "TCP packet with no flags set (NULL scan)",
                })
            elif flags == 0x29:  # FIN+URG+PSH
                findings.append({
                    "type": "XMAS Scan",
                    "severity": "HIGH",
                    "src": src,
                    "dst": f"{dst}:{dport}",
                    "detail": "FIN+URG+PSH set (XMAS scan)",
                })
            elif flags == 0x01:  # FIN only
                findings.append({
                    "type": "FIN Scan",
                    "severity": "HIGH",
                    "src": src,
                    "dst": f"{dst}:{dport}",
                    "detail": "FIN-only flag (FIN scan)",
                })
        return findings[:30]

    def _detect_large_transfers(self) -> list:
        """Detect pairs that transfer more than 1 MB."""
        flow_bytes = defaultdict(int)
        for pkt in self.packets:
            if pkt.haslayer(IP):
                key = (pkt[IP].src, pkt[IP].dst)
                flow_bytes[key] += len(pkt)

        threshold = 1_000_000  # 1 MB
        findings = []
        for (src, dst), total in sorted(flow_bytes.items(), key=lambda x: -x[1]):
            if total >= threshold:
                findings.append({
                    "type": "Large Transfer",
                    "severity": "MEDIUM",
                    "src": src,
                    "dst": dst,
                    "detail": f"{total / 1024 / 1024:.2f} MB transferred",
                })
        return findings[:10]
