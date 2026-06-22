"""
reporters/html_reporter.py - Self-contained HTML report with Chart.js visualizations
"""

import json
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger(__name__)


def _fmt_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b / 1024 ** 2:.1f} MB"
    return f"{b / 1024 ** 3:.2f} GB"


class HTMLReporter:
    def __init__(self, results: dict):
        self.results = results

    def render(self, output_file: str = "report.html"):
        html = self._build_html()
        path = output_file or "report.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"HTML report saved to: {path}")

    def _build_html(self) -> str:
        data = self.results
        modules = data.get("modules", {})
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        traffic = modules.get("traffic", {})
        security = modules.get("security", {})
        dns = modules.get("dns", {})
        http = modules.get("http", {})
        sessions = modules.get("sessions", {})

        js_data = json.dumps(data, default=str)

        proto_labels = json.dumps(list(traffic.get("protocols", {}).keys()))
        proto_values = json.dumps(list(traffic.get("protocols", {}).values()))

        top_src = traffic.get("top_sources", [])
        src_labels = json.dumps([e["ip"] for e in top_src[:8]])
        src_bytes = json.dumps([e["bytes"] for e in top_src[:8]])

        dns_types = dns.get("query_type_dist", {})
        dns_type_labels = json.dumps(list(dns_types.keys()))
        dns_type_values = json.dumps(list(dns_types.values()))

        status_dist = http.get("status_code_distribution", {})
        status_labels = json.dumps([str(k) for k in status_dist.keys()])
        status_values = json.dumps(list(status_dist.values()))

        risk = security.get("risk_level", "UNKNOWN")
        risk_color = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#d69e2e", "LOW": "#38a169"}.get(risk, "#718096")

        alerts_html = ""
        for a in security.get("alerts", []):
            sev_color = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#d69e2e", "LOW": "#2b6cb0"}.get(a["severity"], "#718096")
            alerts_html += f'<div class="alert-item"><span class="badge" style="background:{sev_color}">{a["severity"]}</span> <strong>{a["type"]}</strong>: {a["detail"]}</div>'

        top_domains_html = ""
        for e in dns.get("top_queried_domains", [])[:10]:
            top_domains_html += f'<tr><td>{e["domain"]}</td><td>{e["count"]}</td></tr>'

        top_hosts_html = ""
        for e in http.get("top_hosts", [])[:8]:
            top_hosts_html += f'<tr><td>{e["host"]}</td><td>{e["requests"]}</td></tr>'

        sessions_html = ""
        for s in sessions.get("sessions", [])[:15]:
            sessions_html += f'<tr><td><span class="proto-badge proto-{s["proto"]}">{s["proto"]}</span></td><td>{s["src"]}</td><td>{s["dst"]}</td><td>{s["packets"]}</td><td>{_fmt_bytes(s["bytes"])}</td></tr>'

        findings_html = ""
        for f in security.get("findings", [])[:20]:
            sev_color = {"CRITICAL": "#e53e3e", "HIGH": "#dd6b20", "MEDIUM": "#d69e2e", "LOW": "#2b6cb0"}.get(f.get("severity"), "#718096")
            findings_html += f'<tr><td><span class="badge" style="background:{sev_color}">{f.get("severity","")}</span></td><td>{f.get("type","")}</td><td>{f.get("src","")}</td><td>{f.get("detail","")[:80]}</td></tr>'

        s = traffic.get("summary", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PacketLens Report — {data.get('file','')}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {{--bg:#0f1117;--card:#1a1d27;--card2:#22253a;--accent:#4f8ef7;--text:#e2e8f0;--muted:#718096;--border:#2d3250;}}
  * {{box-sizing:border-box;margin:0;padding:0;}}
  body {{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}}
  header {{background:linear-gradient(135deg,#1a1d27,#252a40);padding:24px 32px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}}
  header h1 {{font-size:1.5rem;background:linear-gradient(90deg,#4f8ef7,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
  header .meta {{color:var(--muted);font-size:12px;text-align:right;}}
  .container {{max-width:1400px;margin:0 auto;padding:24px 32px;}}
  .grid2 {{display:grid;grid-template-columns:1fr 1fr;gap:20px;}}
  .grid3 {{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;}}
  .card {{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;}}
  .card h2 {{font-size:1rem;color:var(--accent);margin-bottom:16px;display:flex;align-items:center;gap:8px;}}
  .stat-grid {{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:24px;}}
  .stat {{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;}}
  .stat .label {{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;}}
  .stat .value {{font-size:1.5rem;font-weight:700;margin-top:4px;color:var(--accent);}}
  .badge {{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;}}
  .alert-item {{padding:8px 12px;border-left:3px solid var(--accent);margin:6px 0;background:var(--card2);border-radius:0 6px 6px 0;}}
  .alert-item .badge {{margin-right:8px;}}
  table {{width:100%;border-collapse:collapse;font-size:13px;}}
  th {{color:var(--muted);font-weight:600;text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;}}
  td {{padding:7px 12px;border-bottom:1px solid rgba(45,50,80,.5);}}
  tr:hover td {{background:var(--card2);}}
  .risk-badge {{display:inline-block;padding:6px 20px;border-radius:20px;font-weight:800;font-size:1.1rem;color:#fff;}}
  .proto-badge {{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;}}
  .proto-TCP {{background:#2b4c8c;color:#90cdf4;}}
  .proto-UDP {{background:#2f5930;color:#9ae6b4;}}
  .chart-wrap {{position:relative;height:240px;}}
  section {{margin-bottom:28px;}}
  section > h2 {{font-size:1.1rem;color:var(--text);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--border);}}
  .tunnel-warn {{background:#7b341e;border:1px solid #c05621;border-radius:8px;padding:10px 16px;color:#fbd38d;font-weight:600;margin-bottom:12px;}}
</style>
</head>
<body>
<header>
  <div>
    <h1>PacketLens Analysis Report</h1>
    <div style="color:var(--muted);margin-top:4px;">File: <strong style="color:var(--text)">{data.get('file','N/A')}</strong></div>
  </div>
  <div class="meta">
    Generated: {ts}<br>
    Packets: <strong>{data.get('packet_count',0):,}</strong>
  </div>
</header>

<div class="container">

<!-- STATS ROW -->
<div class="stat-grid" style="margin-top:8px;">
  <div class="stat"><div class="label">Total Packets</div><div class="value">{s.get('total_packets',0):,}</div></div>
  <div class="stat"><div class="label">Total Bytes</div><div class="value">{_fmt_bytes(s.get('total_bytes',0))}</div></div>
  <div class="stat"><div class="label">Duration</div><div class="value">{s.get('duration_seconds',0):.2f}s</div></div>
  <div class="stat"><div class="label">Avg Pkt Size</div><div class="value">{s.get('avg_packet_size',0):.0f} B</div></div>
  <div class="stat"><div class="label">DNS Queries</div><div class="value">{dns.get('total_queries',0):,}</div></div>
  <div class="stat"><div class="label">Risk Level</div><div class="value" style="color:{risk_color}">{risk}</div></div>
</div>

<!-- TRAFFIC + SECURITY -->
<section>
  <h2>Traffic Overview</h2>
  <div class="grid2">
    <div class="card">
      <h2>Protocol Distribution</h2>
      <div class="chart-wrap"><canvas id="protoChart"></canvas></div>
    </div>
    <div class="card">
      <h2>Top Source IPs (bytes)</h2>
      <div class="chart-wrap"><canvas id="srcChart"></canvas></div>
    </div>
  </div>
</section>

<section>
  <h2>Security</h2>
  <div class="grid2">
    <div class="card">
      <h2>Alerts</h2>
      {alerts_html if alerts_html else '<p style="color:var(--muted)">No alerts</p>'}
    </div>
    <div class="card">
      <h2>Findings</h2>
      {f'<table><thead><tr><th>Sev</th><th>Type</th><th>Src</th><th>Detail</th></tr></thead><tbody>{findings_html}</tbody></table>' if findings_html else '<p style="color:var(--muted)">No findings</p>'}
    </div>
  </div>
</section>

<!-- DNS + HTTP -->
<section>
  <h2>DNS &amp; HTTP</h2>
  <div class="grid2">
    <div class="card">
      <h2>DNS Query Types</h2>
      {"<div class='tunnel-warn'>DNS Tunneling Risk Detected</div>" if dns.get('tunneling_risk') else ""}
      <div class="chart-wrap"><canvas id="dnsChart"></canvas></div>
      <h2 style="margin-top:16px;">Top Queried Domains</h2>
      <table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>{top_domains_html}</tbody></table>
    </div>
    <div class="card">
      <h2>HTTP Status Codes</h2>
      <div class="chart-wrap"><canvas id="httpChart"></canvas></div>
      <h2 style="margin-top:16px;">Top Hosts</h2>
      <table><thead><tr><th>Host</th><th>Requests</th></tr></thead><tbody>{top_hosts_html}</tbody></table>
    </div>
  </div>
</section>

<!-- SESSIONS -->
{"<section><h2>Sessions</h2><div class='card'><table><thead><tr><th>Proto</th><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>" + sessions_html + "</tbody></table></div></section>" if sessions_html else ""}

</div><!-- /container -->

<script>
const COLORS = ['#4f8ef7','#a78bfa','#f687b3','#fbd38d','#9ae6b4','#63b3ed','#fc8181','#b794f4','#76e4f7','#faf089'];

new Chart(document.getElementById('protoChart'), {{
  type: 'doughnut',
  data: {{ labels: {proto_labels}, datasets: [{{ data: {proto_values}, backgroundColor: COLORS, borderWidth:2, borderColor:'#1a1d27' }}] }},
  options: {{ responsive:true, maintainAspectRatio:false, plugins:{{ legend:{{ position:'right', labels:{{ color:'#e2e8f0', font:{{size:11}} }} }} }} }}
}});

new Chart(document.getElementById('srcChart'), {{
  type: 'bar',
  data: {{ labels: {src_labels}, datasets: [{{ label:'Bytes', data: {src_bytes}, backgroundColor:'#4f8ef7', borderRadius:4 }}] }},
  options: {{ responsive:true, maintainAspectRatio:false, indexAxis:'y', plugins:{{ legend:{{display:false}} }}, scales:{{ x:{{ ticks:{{ color:'#718096' }} }}, y:{{ ticks:{{ color:'#e2e8f0', font:{{size:11}} }} }} }} }}
}});

new Chart(document.getElementById('dnsChart'), {{
  type: 'pie',
  data: {{ labels: {dns_type_labels}, datasets: [{{ data: {dns_type_values}, backgroundColor: COLORS, borderWidth:2, borderColor:'#1a1d27' }}] }},
  options: {{ responsive:true, maintainAspectRatio:false, plugins:{{ legend:{{ position:'right', labels:{{ color:'#e2e8f0', font:{{size:11}} }} }} }} }}
}});

new Chart(document.getElementById('httpChart'), {{
  type: 'bar',
  data: {{ labels: {status_labels}, datasets: [{{ label:'Count', data: {status_values}, backgroundColor: COLORS, borderRadius:4 }}] }},
  options: {{ responsive:true, maintainAspectRatio:false, plugins:{{ legend:{{display:false}} }}, scales:{{ x:{{ ticks:{{ color:'#e2e8f0' }} }}, y:{{ ticks:{{ color:'#718096' }} }} }} }}
}});
</script>
</body>
</html>"""
