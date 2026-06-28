# PacketLens — Packet Capture Analysis Tool

A full-featured network traffic analyzer built with **Scapy**. Supports offline PCAP analysis, live capture, security detection, DNS/HTTP inspection, session reconstruction, and HTML/JSON reporting.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate a sample PCAP (no root needed)
python main.py sample --output test.pcap

# Analyze with all modules
python main.py analyze -f test.pcap --all

# Export HTML report
python main.py analyze -f test.pcap --all --report html --output report.html

# Export JSON
python main.py analyze -f test.pcap --all --report json --output results.json

# Analyze with a specific module only
python main.py analyze -f test.pcap --security
python main.py analyze -f test.pcap --dns --top 20
python main.py analyze -f test.pcap --http

# Apply a BPF-style filter
python main.py analyze -f test.pcap --filter "tcp port 80" --all

# Live capture (requires root)
sudo python main.py capture --interface eth0 --count 200 --output live.pcap

# List network interfaces
python main.py info
```

---

## Security Detection Capabilities

- **Port Scans**: Detects SYN sweeps across ≥15 distinct ports from one source
- **TCP Flag Anomalies**: NULL scan (no flags), XMAS scan (FIN+URG+PSH), FIN-only scan
- **Cleartext Protocols**: Telnet, FTP, TFTP, rsh/rlogin, SNMP, known backdoor ports
- **Credential Exposure**: FTP USER/PASS, HTTP Basic Auth, form password fields
- **ICMP Tunneling**: Oversized ICMP packets (>1KB)
- **DNS Tunneling**: Oversized labels, high NXDOMAIN ratio
- **DGA Domains**: Low vowel ratio heuristic on second-level domain labels
- **Large Transfers**: Flows exceeding 1 MB flagged for investigation
- **Risk Score**: Weighted aggregate score → LOW / MEDIUM / HIGH / CRITICAL

---

## Notes

- Live capture requires root/administrator privileges
- BPF filter support for offline PCAPs is keyword-based (not full libpcap)
- The sample PCAP generator creates realistic traffic including intentional red flags for testing
