"""
monitor.py — Panel web de monitoreo del proxy (puerto 8888)
Importa el estado compartido desde proxy.py
"""
import json
import csv
import io
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

# Se importa el estado compartido del proxy
from proxy import stats, stats_lock, LOG_FILE


def get_snapshot():
    """Toma una copia thread-safe de las estadísticas."""
    with stats_lock:
        total    = stats["total_requests"]
        blocked  = stats["blocked"]
        allowed  = stats["allowed"]
        bytes_t  = stats["total_bytes"]
        domains  = dict(stats["domains"])
        clients  = dict(stats["clients"])
        log      = list(stats["requests_log"])

    top5 = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:5]
    pct_blocked = round((blocked / total * 100), 1) if total else 0
    pct_allowed = round((allowed / total * 100), 1) if total else 0

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "pct_blocked": pct_blocked,
        "pct_allowed": pct_allowed,
        "mb": round(bytes_t / (1024 * 1024), 3),
        "top5": top5,
        "clients": sorted(clients.items(), key=lambda x: x[1], reverse=True),
        "log": log[-50:][::-1],   # últimas 50, más reciente primero
    }


PANEL_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Proxy Monitor</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

  :root {
    --bg: #0a0c0f;
    --surface: #111418;
    --border: #1e2530;
    --accent: #00e5a0;
    --accent2: #ff4d6d;
    --accent3: #4d9fff;
    --text: #c8d0dc;
    --muted: #5a6475;
    --card: #13171e;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 32px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }

  header h1 {
    font-size: 1.3rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--accent);
  }

  .badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    padding: 4px 10px;
    border-radius: 4px;
    border: 1px solid var(--accent);
    color: var(--accent);
  }

  .refresh-info {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--muted);
  }

  main { padding: 28px 32px; }

  /* ---- KPI Grid ---- */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }

  .kpi {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }

  .kpi::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--accent-line, var(--accent));
  }

  .kpi.red   { --accent-line: var(--accent2); }
  .kpi.blue  { --accent-line: var(--accent3); }
  .kpi.green { --accent-line: var(--accent);  }

  .kpi-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 8px;
  }

  .kpi-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    line-height: 1;
    color: #fff;
  }

  .kpi-sub {
    font-size: 0.72rem;
    color: var(--muted);
    margin-top: 6px;
  }

  /* ---- Two column layout ---- */
  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
  }

  @media (max-width: 760px) { .two-col { grid-template-columns: 1fr; } }

  .panel {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
  }

  .panel-title {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--muted);
    margin-bottom: 16px;
  }

  /* Bar chart */
  .bar-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
    font-size: 0.8rem;
  }

  .bar-label { width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
  .bar-track { flex: 1; background: var(--border); border-radius: 3px; height: 8px; }
  .bar-fill  { height: 100%; border-radius: 3px; background: var(--accent); transition: width 0.4s; }
  .bar-count { font-family: 'JetBrains Mono', monospace; color: var(--muted); font-size: 0.7rem; width: 40px; text-align: right; }

  /* Donut chart */
  .donut-wrap { display: flex; align-items: center; gap: 20px; }
  .donut-legend { display: flex; flex-direction: column; gap: 8px; }
  .legend-item { display: flex; align-items: center; gap: 8px; font-size: 0.78rem; }
  .legend-dot  { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

  /* Client table */
  .ctable { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  .ctable th {
    text-align: left;
    color: var(--muted);
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 0 0 10px;
    border-bottom: 1px solid var(--border);
  }
  .ctable td {
    padding: 8px 0;
    border-bottom: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }
  .ctable tr:last-child td { border-bottom: none; }

  /* Log table */
  .log-panel { margin-bottom: 28px; }

  .log-table-wrap { overflow-x: auto; }
  .log-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.75rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .log-table th {
    text-align: left;
    padding: 8px 12px;
    background: var(--surface);
    color: var(--muted);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    white-space: nowrap;
  }
  .log-table td { padding: 7px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .log-table tr:hover td { background: rgba(255,255,255,0.02); }

  .status-ALLOWED { color: var(--accent); }
  .status-BLOCKED { color: var(--accent2); }
  .status-ERROR   { color: #f0a500; }

  /* Export button */
  .toolbar { display: flex; gap: 10px; margin-bottom: 20px; }
  .btn {
    font-family: 'Syne', sans-serif;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    padding: 8px 18px;
    border-radius: 6px;
    border: 1px solid var(--accent);
    background: transparent;
    color: var(--accent);
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
    transition: background 0.2s, color 0.2s;
  }
  .btn:hover { background: var(--accent); color: var(--bg); }
  .btn.json { border-color: var(--accent3); color: var(--accent3); }
  .btn.json:hover { background: var(--accent3); color: var(--bg); }
</style>
</head>
<body>

<header>
  <h1>⬡ Proxy Monitor</h1>
  <div style="display:flex;gap:16px;align-items:center">
    <span class="refresh-info" id="lastUpdate">—</span>
    <span class="badge">LIVE</span>
  </div>
</header>

<main>
  <!-- KPIs -->
  <div class="kpi-grid" id="kpis"></div>

  <!-- Charts row -->
  <div class="two-col">
    <div class="panel" id="topDomains">
      <div class="panel-title">Top 5 dominios</div>
      <div id="barChart"></div>
    </div>
    <div class="panel" id="statusPanel">
      <div class="panel-title">Permitidas vs bloqueadas</div>
      <div class="donut-wrap">
        <svg id="donut" width="120" height="120" viewBox="0 0 120 120"></svg>
        <div class="donut-legend" id="donutLegend"></div>
      </div>
    </div>
  </div>

  <!-- Clients -->
  <div class="two-col" style="margin-bottom:28px">
    <div class="panel">
      <div class="panel-title">Clientes activos</div>
      <table class="ctable" id="clientTable">
        <thead><tr><th>IP</th><th>Solicitudes</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Exportar logs</div>
      <p style="color:var(--muted);font-size:0.82rem;margin-bottom:16px">
        Descarga el historial completo de solicitudes registradas.
      </p>
      <div class="toolbar">
        <a class="btn" href="/export/csv" target="_blank">⬇ CSV</a>
        <a class="btn json" href="/export/json" target="_blank">⬇ JSON</a>
      </div>
    </div>
  </div>

  <!-- Log table -->
  <div class="panel log-panel">
    <div class="panel-title">Últimas solicitudes</div>
    <div class="log-table-wrap">
      <table class="log-table" id="logTable">
        <thead>
          <tr>
            <th>Timestamp</th><th>Cliente IP</th><th>Método</th>
            <th>Dominio</th><th>Estado</th><th>Bytes</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</main>

<script>
async function fetchData() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    render(d);
    document.getElementById('lastUpdate').textContent =
      'Actualizado: ' + new Date().toLocaleTimeString('es-CR');
  } catch(e) { console.error(e); }
}

function render(d) {
  // KPIs
  document.getElementById('kpis').innerHTML = `
    <div class="kpi green">
      <div class="kpi-label">Total solicitudes</div>
      <div class="kpi-value">${d.total}</div>
    </div>
    <div class="kpi blue">
      <div class="kpi-label">Datos transferidos</div>
      <div class="kpi-value">${d.mb}</div>
      <div class="kpi-sub">megabytes</div>
    </div>
    <div class="kpi green">
      <div class="kpi-label">Permitidas</div>
      <div class="kpi-value">${d.allowed}</div>
      <div class="kpi-sub">${d.pct_allowed}%</div>
    </div>
    <div class="kpi red">
      <div class="kpi-label">Bloqueadas</div>
      <div class="kpi-value">${d.blocked}</div>
      <div class="kpi-sub">${d.pct_blocked}%</div>
    </div>
  `;

  // Bar chart
  const maxVal = d.top5.length ? d.top5[0][1] : 1;
  document.getElementById('barChart').innerHTML = d.top5.map(([dom, cnt]) => `
    <div class="bar-row">
      <span class="bar-label" title="${dom}">${dom}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(cnt/maxVal*100).toFixed(1)}%"></div></div>
      <span class="bar-count">${cnt}</span>
    </div>
  `).join('') || '<span style="color:var(--muted);font-size:0.8rem">Sin datos aún</span>';

  // Donut
  drawDonut(d.allowed, d.blocked);
  document.getElementById('donutLegend').innerHTML = `
    <div class="legend-item"><span class="legend-dot" style="background:#00e5a0"></span>${d.allowed} permitidas (${d.pct_allowed}%)</div>
    <div class="legend-item"><span class="legend-dot" style="background:#ff4d6d"></span>${d.blocked} bloqueadas (${d.pct_blocked}%)</div>
  `;

  // Clients
  const tb = document.querySelector('#clientTable tbody');
  tb.innerHTML = d.clients.map(([ip, cnt]) =>
    `<tr><td>${ip}</td><td>${cnt}</td></tr>`
  ).join('') || '<tr><td colspan="2" style="color:var(--muted)">Sin clientes</td></tr>';

  // Log table
  const lb = document.querySelector('#logTable tbody');
  lb.innerHTML = d.log.map(row => `
    <tr>
      <td>${row.timestamp}</td>
      <td>${row.client_ip}</td>
      <td>${row.method}</td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis" title="${row.domain}">${row.domain}</td>
      <td class="status-${row.status}">${row.status}</td>
      <td>${row.bytes}</td>
    </tr>
  `).join('') || '<tr><td colspan="6" style="color:var(--muted);padding:12px">Sin solicitudes registradas</td></tr>';
}

function drawDonut(allowed, blocked) {
  const svg = document.getElementById('donut');
  const total = allowed + blocked || 1;
  const r = 45, cx = 60, cy = 60, stroke = 14;
  const circumference = 2 * Math.PI * r;
  const allowedDash = (allowed / total) * circumference;
  const blockedDash = (blocked / total) * circumference;

  svg.innerHTML = `
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#1e2530" stroke-width="${stroke}"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
      stroke="#00e5a0" stroke-width="${stroke}"
      stroke-dasharray="${allowedDash} ${circumference}"
      stroke-dashoffset="${circumference * 0.25}"
      stroke-linecap="butt"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none"
      stroke="#ff4d6d" stroke-width="${stroke}"
      stroke-dasharray="${blockedDash} ${circumference}"
      stroke-dashoffset="${circumference * 0.25 - allowedDash}"
      stroke-linecap="butt"/>
    <text x="${cx}" y="${cy+6}" text-anchor="middle"
      font-family="JetBrains Mono,monospace" font-size="14" fill="#fff" font-weight="700">${total}</text>
  `;
}

fetchData();
setInterval(fetchData, 5000);   // auto-refresh cada 5 s
</script>
</body>
</html>
"""


class MonitorHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass   # silenciar logs del servidor HTTP del panel

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PANEL_HTML.encode())

        elif self.path == "/api/stats":
            snap = get_snapshot()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(json.dumps(snap).encode())

        elif self.path == "/export/csv":
            self._export_csv()

        elif self.path == "/export/json":
            self._export_json()

        else:
            self.send_response(404)
            self.end_headers()

    def _export_csv(self):
        with stats_lock:
            log = list(stats["requests_log"])
        buf = io.StringIO()
        if log:
            writer = csv.DictWriter(buf, fieldnames=log[0].keys())
            writer.writeheader()
            writer.writerows(log)
        content = buf.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", "attachment; filename=proxy_log.csv")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _export_json(self):
        with stats_lock:
            log = list(stats["requests_log"])
        content = json.dumps(log, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", "attachment; filename=proxy_log.json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def start_monitor(port=8888):
    server = ThreadingHTTPServer(("0.0.0.0", port), MonitorHandler)
    print(f"[+] Monitor panel on http://localhost:{port}")
    server.serve_forever()