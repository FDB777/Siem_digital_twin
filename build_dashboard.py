import csv
import json
import random
from correlation_engine import connect_alerts_into_chains
from digital_twin import build_connections_map, simulate_one_outbreak
from recommend import RECOMMENDED_ACTIONS
with open("topology.json") as file:
    topology = json.load(file)

with open("siem_logs.csv", newline="") as file:
    all_logs = list(csv.DictReader(file))

with open("alerts.csv", newline="") as file:
    all_alerts = list(csv.DictReader(file))

chains = connect_alerts_into_chains(all_alerts)

hostname_to_id = {}
role_by_node = {}
vulnerability_by_node = {}
criticality_by_node = {}
for node in topology["nodes"]:
    hostname_to_id[node["hostname"]] = node["id"]
    role_by_node[node["id"]] = node["role"]
    vulnerability_by_node[node["id"]] = node["patch_level"]
    criticality_by_node[node["id"]] = node["criticality"]

connections = build_connections_map(topology)
all_node_ids = list(vulnerability_by_node.keys())
TRIALS = 3000
predictions_by_seed = {}

for seed_node in all_node_ids:
    random_generator = random.Random(7)
    times_infected = {}
    for node_id in all_node_ids:
        if node_id != seed_node:
            times_infected[node_id] = 0

    for _ in range(TRIALS):
        result = simulate_one_outbreak(seed_node, connections, vulnerability_by_node, random_generator)
        for node_id in result:
            if node_id != seed_node:
                times_infected[node_id] += 1

    predictions_for_this_seed = {}
    for node_id, count in times_infected.items():
        probability = round(count / TRIALS, 3)
        impact_score = round(probability * criticality_by_node[node_id], 3)
        predictions_for_this_seed[node_id] = {"probability": probability, "impact_score": impact_score}

    predictions_by_seed[seed_node] = predictions_for_this_seed
DATA_JSON = json.dumps({
    "topology": topology,
    "logs": all_logs,
    "alerts": all_alerts,
    "chains": chains,
    "hostname_to_id": hostname_to_id,
    "role_by_id": role_by_node,
    "predictions": predictions_by_seed,
    "actions": RECOMMENDED_ACTIONS,
})

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Dashboard — FakeCorp Network</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #F4F6F8;
    --surface: #FFFFFF;
    --border: #E3E7EC;
    --text: #1B2430;
    --text-dim: #64707E;
    --text-faint: #98A2AF;
    --brand: #2D5FE0;
    --brand-soft: #EAF0FE;
    --critical: #D93A3A;
    --critical-soft: #FDEDED;
    --high: #E08B1D;
    --high-soft: #FDF3E4;
    --medium: #C9A227;
    --info: #1C9C8B;
    --info-soft: #E8F7F5;
    --safe: #2E9E5B;
    --shadow: 0 1px 2px rgba(20,30,50,0.04), 0 4px 12px rgba(20,30,50,0.05);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: 'Inter', sans-serif; -webkit-font-smoothing: antialiased;
  }
  .mono { font-family: 'JetBrains Mono', monospace; }

  .topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 32px; background: var(--surface); border-bottom: 1px solid var(--border);
  }
  .topbar h1 { font-size: 17px; font-weight: 700; margin: 0; }
  .topbar .sub { font-size: 12px; color: var(--text-dim); margin-top: 2px; }
  .metrics { display: flex; gap: 28px; }
  .metric .num { font-size: 20px; font-weight: 700; }
  .metric .label { font-size: 11px; color: var(--text-dim); margin-top: 2px; }
  .metric.critical .num { color: var(--critical); }

  .main { max-width: 1240px; margin: 0 auto; padding: 28px 32px; }

  .section-title {
    font-size: 13px; font-weight: 600; color: var(--text-dim);
    text-transform: uppercase; letter-spacing: 0.04em; margin: 0 0 14px 0;
  }

  /* Critical alert banner */
  .alert-strip { display: flex; gap: 14px; overflow-x: auto; padding-bottom: 6px; margin-bottom: 32px; }
  .alert-card {
    flex: 0 0 auto; min-width: 280px; background: var(--surface); border: 1px solid var(--border);
    border-left: 4px solid var(--critical); border-radius: 10px; padding: 14px 16px;
    box-shadow: var(--shadow); cursor: pointer; transition: transform 0.15s ease, box-shadow 0.15s ease;
  }
  .alert-card:hover { transform: translateY(-2px); box-shadow: 0 4px 16px rgba(20,30,50,0.10); }
  .alert-card.high { border-left-color: var(--high); }
  .alert-card .sev {
    display: inline-block; font-size: 10px; font-weight: 700; text-transform: uppercase;
    padding: 2px 8px; border-radius: 4px; background: var(--critical-soft); color: var(--critical); margin-bottom: 8px;
  }
  .alert-card.high .sev { background: var(--high-soft); color: var(--high); }
  .alert-card .route { font-size: 13px; font-weight: 600; margin-bottom: 4px; }
  .alert-card .desc { font-size: 12px; color: var(--text-dim); line-height: 1.4; }
  .alert-card .meta { font-size: 11px; color: var(--text-faint); margin-top: 8px; }

  /* Log table */
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; box-shadow: var(--shadow); }
  .search-row { margin-bottom: 14px; }
  input[type=text] {
    width: 100%; padding: 10px 14px; border: 1px solid var(--border); border-radius: 8px;
    font-family: 'Inter', sans-serif; font-size: 13px; background: var(--bg); color: var(--text);
  }
  input[type=text]:focus { outline: none; border-color: var(--brand); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th {
    text-align: left; font-size: 10.5px; font-weight: 700; text-transform: uppercase; color: var(--text-dim);
    letter-spacing: 0.03em; padding: 9px 10px; border-bottom: 1px solid var(--border);
    position: sticky; top: 0; background: var(--surface);
  }
  td { padding: 8px 10px; border-bottom: 1px solid #EEF1F4; color: var(--text); }
  tr:hover td { background: #FAFBFC; }
  .table-scroll { max-height: 480px; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; }
  .badge { display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 10.5px; font-weight: 600; }
  .badge.critical { background: var(--critical-soft); color: var(--critical); }
  .badge.high { background: var(--high-soft); color: var(--high); }
  .badge.medium { background: #FBF6E3; color: var(--medium); }
  .badge.info { background: var(--info-soft); color: var(--info); }

  /* Modal */
  .overlay {
    display: none; position: fixed; inset: 0; background: rgba(20,30,50,0.45);
    align-items: center; justify-content: center; z-index: 100; padding: 24px;
  }
  .overlay.open { display: flex; }
  .modal {
    background: var(--surface); border-radius: 14px; width: 100%; max-width: 780px;
    max-height: 88vh; overflow-y: auto; padding: 28px; box-shadow: 0 20px 60px rgba(0,0,0,0.25);
  }
  .modal-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 18px; }
  .modal-head h2 { font-size: 16px; margin: 0 0 4px; }
  .modal-head .desc { font-size: 13px; color: var(--text-dim); max-width: 560px; }
  .close-btn {
    background: var(--bg); border: 1px solid var(--border); border-radius: 8px; width: 32px; height: 32px;
    font-size: 15px; cursor: pointer; color: var(--text-dim); flex-shrink: 0;
  }
  .close-btn:hover { background: var(--border); }

  .modal-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; }
  @media (max-width: 700px) { .modal-grid { grid-template-columns: 1fr; } }

  .rank-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 9px 0; border-bottom: 1px solid #EEF1F4; font-size: 12.5px;
  }
  .rank-row:last-child { border-bottom: none; }
  .rank-node { font-weight: 600; }
  .rank-prob { font-family: 'JetBrains Mono', monospace; color: var(--text-dim); font-size: 12px; }
  .bar-bg { background: #EEF1F4; border-radius: 4px; height: 6px; margin-top: 5px; overflow: hidden; }
  .bar-fill { background: var(--critical); height: 100%; border-radius: 4px; }

  .action-card {
    background: var(--brand-soft); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 12px; color: #1E3E9E;
  }
</style>
</head>
<body>

<div class="topbar">
  <div>
    <h1>FakeCorp Network — Security Dashboard</h1>
    <div class="sub">Digital twin monitoring &amp; predictive spread analysis</div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="num" id="m-events">-</div><div class="label">Events</div></div>
    <div class="metric"><div class="num" id="m-alerts">-</div><div class="label">Alerts</div></div>
    <div class="metric critical"><div class="num" id="m-critical">-</div><div class="label">Critical/High</div></div>
  </div>
</div>

<div class="main">
  <div class="section-title">Critical &amp; high severity alerts — click for predicted impact</div>
  <div class="alert-strip" id="alert-strip"></div>

  <div class="section-title">Raw log feed</div>
  <div class="panel">
    <div class="search-row"><input type="text" id="log-search" placeholder="Search by host, user, process, event type..."></div>
    <div class="table-scroll">
      <table>
        <thead><tr><th>Timestamp</th><th>Src Host</th><th>Dst Host</th><th>User</th><th>Event Type</th><th>Process</th><th>Severity</th></tr></thead>
        <tbody id="log-tbody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="overlay" id="overlay">
  <div class="modal">
    <div class="modal-head">
      <div>
        <h2 id="modal-title">Predicted impact</h2>
        <div class="desc" id="modal-desc"></div>
      </div>
      <button class="close-btn" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-grid">
      <div>
        <div class="section-title" style="margin-bottom:10px;">Nodes likely affected next</div>
        <div id="modal-ranking"></div>
      </div>
      <div>
        <div class="section-title" style="margin-bottom:10px;">Top recommended actions</div>
        <div id="modal-actions"></div>
      </div>
    </div>
  </div>
</div>

<script>
const DATA = __DATA_JSON__;

document.getElementById('m-events').textContent = DATA.logs.length;
document.getElementById('m-alerts').textContent = DATA.alerts.length;
const criticalAlerts = DATA.alerts.filter(a => a.severity === 'critical' || a.severity === 'high')
  .sort((a,b) => b.alert_score - a.alert_score);
document.getElementById('m-critical').textContent = criticalAlerts.length;

function sevBadge(sev) { return `<span class="badge ${sev}">${sev}</span>`; }

// --- Critical alert strip ---
document.getElementById('alert-strip').innerHTML = criticalAlerts.map((a, i) => `
  <div class="alert-card ${a.severity === 'high' ? 'high' : ''}" onclick="openModal(${i})">
    <div class="sev">${a.severity}</div>
    <div class="route">${a.src_host || '—'} &rarr; ${a.dst_host || '—'}</div>
    <div class="desc">${a.description}</div>
    <div class="meta">${a.timestamp} · score ${a.alert_score}</div>
  </div>
`).join('');

// --- Log feed table ---
function renderLogs(filter) {
  const f = (filter || '').toLowerCase();
  document.getElementById('log-tbody').innerHTML = DATA.logs
    .filter(r => !f || Object.values(r).join(' ').toLowerCase().includes(f))
    .map(r => `<tr>
      <td class="mono">${r.timestamp}</td><td>${r.src_host || '-'}</td><td>${r.dst_host || '-'}</td>
      <td>${r.user}</td><td>${r.event_type}</td><td class="mono">${r.process || '-'}</td>
      <td>${sevBadge(r.severity)}</td>
    </tr>`).join('');
}
renderLogs('');
document.getElementById('log-search').addEventListener('input', e => renderLogs(e.target.value));

// --- Modal: click an alert -> show digital twin prediction for that host ---
function openModal(idx) {
  const alert = criticalAlerts[idx];
  const host = alert.dst_host || alert.src_host;
  const seedId = DATA.hostname_to_id[host];
  const overlay = document.getElementById('overlay');

  document.getElementById('modal-title').textContent = `Predicted spread from ${host}`;
  document.getElementById('modal-desc').textContent = alert.description;

  if (!seedId || !DATA.predictions[seedId]) {
    document.getElementById('modal-ranking').innerHTML = '<p style="font-size:12px; color:var(--text-faint);">No propagation model available for this host.</p>';
    document.getElementById('modal-actions').innerHTML = '';
    overlay.classList.add('open');
    return;
  }

  const preds = DATA.predictions[seedId];
  const ranked = Object.entries(preds).sort((a,b) => b[1].impact_score - a[1].impact_score);
  const maxProb = Math.max(...ranked.map(([,v]) => v.probability), 0.01);

  document.getElementById('modal-ranking').innerHTML = ranked.map(([node, v]) => `
    <div class="rank-row" style="display:block;">
      <div style="display:flex; justify-content:space-between;">
        <span class="rank-node">${node} <span style="color:var(--text-faint); font-weight:400;">(${DATA.role_by_id[node]})</span></span>
        <span class="rank-prob">P=${v.probability}</span>
      </div>
      <div class="bar-bg"><div class="bar-fill" style="width:${(v.probability/maxProb)*100}%;"></div></div>
    </div>
  `).join('');

  document.getElementById('modal-actions').innerHTML = ranked.slice(0, 3).map(([node, v]) => `
    <div class="action-card">
      <strong>${node}</strong> (${DATA.role_by_id[node]}) — impact ${v.impact_score}<br>
      ${DATA.actions[DATA.role_by_id[node]] || 'Isolate and investigate.'}
    </div>
  `).join('');

  overlay.classList.add('open');
}
function closeModal() { document.getElementById('overlay').classList.remove('open'); }
document.getElementById('overlay').addEventListener('click', e => { if (e.target.id === 'overlay') closeModal(); });
</script>

</body>
</html>
"""

open("dashboard.html", "w").write(HTML_TEMPLATE.replace("__DATA_JSON__", DATA_JSON))
print("Done! Saved dashboard.html -- open it in your web browser.")
