import sys
import json
from pathlib import Path
from flask import Flask, jsonify, render_template_string

# Database import
sys.path.insert(0, '..')
from analyzers.database import ScamDatabase

app = Flask(__name__)

def get_latest_report():
    # Pehle JSON file check karo
    reports = sorted(Path('../output').glob('scam_report_*.json'))

    # Database se bhi data lo
    try:
        db = ScamDatabase('../scam_data.db')
        db_stats = db.export_for_report()
        db.close()
    except Exception as e:
        db_stats = None

    if not reports and not db_stats:
        return None

    # JSON report load karo
    report_data = None
    if reports:
        with open(reports[-1]) as f:
            report_data = json.load(f)

    # Database stats merge karo
    if db_stats:
        if report_data:
            report_data['database_stats'] = db_stats['statistics']
            report_data['database_stats']['suspicious_iocs'] = db_stats.get(
                'suspicious_iocs',
                []
            )
            report_data['database_stats']['graph_data'] = db_stats.get(
                'graph_data',
                []
            )
            report_data['database_recent'] = db_stats['recent_high_risk']
        else:
            report_data = {
                'scan_info': {'timestamp': 'From Database'},
                'summary': {
                    'total_collected': db_stats['statistics']['total_content'],
                    'total_flagged': len(db_stats['recent_high_risk']),
                    'by_risk': db_stats['statistics']['risk_distribution'],
                    'by_platform': db_stats['statistics']['platform_distribution'],
                    'top_categories': {}
                },
                'database_stats': db_stats['statistics'],
                'critical_findings': [],
                'high_risk_findings': db_stats['recent_high_risk'],
                'all_flagged': db_stats['recent_high_risk']
            }

    return report_data


HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Scam Monitor Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a1a; color: #e0e0e0; padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #1a1a3e, #0a0a1a);
            padding: 30px; border-radius: 15px; margin-bottom: 30px;
            border-bottom: 3px solid #e94560;
        }
        .header h1 { font-size: 2em; color: #e94560; }
        .header p { color: #888; margin-top: 10px; }
        .refresh-btn {
            background: #e94560; color: white; border: none;
            padding: 10px 25px; border-radius: 8px; cursor: pointer;
            font-size: 1em; margin-top: 15px;
        }
        .refresh-btn:hover { background: #d63850; }

        .stats-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }
        .stat-card {
            background: #1a1a2e; padding: 25px; border-radius: 12px;
            border-left: 5px solid #e94560;
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-3px); }
        .stat-card h3 { font-size: 0.9em; color: #888; margin-bottom: 8px; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; }
        .stat-card .label { font-size: 0.8em; color: #666; margin-top: 5px; }

        .charts {
            display: grid; grid-template-columns: 1fr 1fr;
            gap: 20px; margin-bottom: 30px;
        }
        @media (max-width: 768px) { .charts { grid-template-columns: 1fr; } }
        .chart-box {
            background: #1a1a2e; padding: 20px; border-radius: 12px;
        }
        .chart-box h3 { margin-bottom: 15px; color: #aaa; }

        .section {
            background: #1a1a2e; padding: 20px; border-radius: 12px;
            margin-bottom: 30px;
        }
        .section h2 { color: #e94560; margin-bottom: 20px; }

        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4e; }
        th { color: #888; font-weight: normal; text-transform: uppercase; font-size: 0.8em; }

        a { color: #4a9eff; text-decoration: none; }
        a:hover { text-decoration: underline; }

        .badge {
            padding: 3px 12px; border-radius: 12px; font-size: 0.8em; font-weight: bold;
        }
        .badge-CRITICAL { background: #ff4444; color: white; }
        .badge-HIGH { background: #ff8800; color: white; }
        .badge-MEDIUM { background: #ffcc00; color: #333; }
        .badge-LOW { background: #00cc44; color: white; }

        .entity-item {
            padding: 12px; border-bottom: 1px solid #2a2a4e;
            display: flex; justify-content: space-between; align-items: center;
        }
        .entity-item:last-child { border-bottom: none; }

        .db-section {
            background: #1a2a1a; border-left: 5px solid #00cc44;
            padding: 20px; border-radius: 12px; margin-bottom: 30px;
        }
        .db-section h2 { color: #00cc44; }

        .entity-chip {
            display: inline-block;
            background: #2a2a4e; padding: 4px 12px;
            border-radius: 15px; margin: 3px; font-size: 0.85em;
        }
        .entity-chip.phone { border: 1px solid #4a9eff; color: #4a9eff; }
        .entity-chip.upi { border: 1px solid #ff8800; color: #ff8800; }
        .entity-chip.email { border: 1px solid #ffcc00; color: #ffcc00; }

        .tab-container { margin-bottom: 30px; }
        .tab-btn {
            padding: 10px 20px; background: #1a1a2e; border: none;
            color: #888; cursor: pointer; border-radius: 8px 8px 0 0;
            font-size: 0.9em;
        }
        .tab-btn.active { background: #e94560; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Social Scam Monitor</h1>
        <p id="timestamp">Loading...</p>
        <button class="refresh-btn" onclick="refresh()">🔄 Refresh Data</button>
    </div>

    <!-- Stats Grid -->
    <div class="stats-grid" id="statsGrid"></div>

    <!-- Charts -->
    <div class="charts">
        <div class="chart-box">
            <h3>Risk Distribution</h3>
            <canvas id="riskChart"></canvas>
        </div>
        <div class="chart-box">
            <h3>Content by Platform</h3>
            <canvas id="platformChart"></canvas>
        </div>
    </div>

    <!-- Tabs -->
    <div class="tab-container">
        <button class="tab-btn active" onclick="switchTab('flagged')">🚩 Flagged Content</button>
        <button class="tab-btn" onclick="switchTab('entities')">📞 Entities (Phone/UPI)</button>
        <button class="tab-btn" onclick="switchTab('database')">🗄️ Database Stats</button>
        <button class="tab-btn" onclick="switchTab('iocs')">🎯 Top Suspicious IOCs</button>
    </div>

    <!-- Tab: Flagged Content -->
    <div id="tab-flagged" class="tab-content active">
        <div class="section">
            <h2>🚩 Critical & High Risk Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Risk</th><th>Platform</th><th>Title</th><th>Views</th><th>Link</th>
                    </tr>
                </thead>
                <tbody id="findingsTable"></tbody>
            </table>
        </div>
    </div>

    <!-- Tab: Entities -->
    <div id="tab-entities" class="tab-content">
        <div class="section">
            <h2>📞 Top Phone Numbers</h2>
            <div id="phoneEntities"></div>
        </div>
        <div class="section">
            <h2>💳 Top UPI IDs</h2>
            <div id="upiEntities"></div>
        </div>
        <div class="section">
            <h2>📧 Top Emails</h2>
            <div id="emailEntities"></div>
        </div>

        <div class="section">
            <h2>👤 Telegram Usernames</h2>
            <div id="telegramEntities"></div>
        </div>

        <div class="section">
            <h2>🌐 Domains</h2>
            <div id="domainEntities"></div>
        </div>

        <div class="section">
            <h2>₿ Crypto Wallets</h2>
            <div id="walletEntities"></div>
        </div>
    </div>

    <!-- Tab: IOC Reputation -->
    <div id="tab-iocs" class="tab-content">
        <div class="section">
            <h2>🎯 Top Suspicious IOCs</h2>
            <div id="iocTable"></div>
        </div>
        <div class="section">
            <h2>🕸 IOC Relationship Graph</h2>
            <div id="networkGraph"
                 style="height:600px;
                        background:#111;
                        border-radius:10px;">
            </div>
        </div>
    </div>

    <!-- Tab: Database -->
    <div id="tab-database" class="tab-content">
        <div class="db-section">
            <h2>🗄️ Database Overview</h2>
            <div id="dbStats"></div>
        </div>
        <div class="section">
            <h2>📊 Scan History</h2>
            <div id="scanHistory"></div>
        </div>
        <div class="section">
            <h2>🔗 Cross-Platform Links</h2>
            <div id="crossPlatform"></div>
        </div>
    </div>

    <script>
        let riskChartInstance = null;
        let platformChartInstance = null;

        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');
            event.target.classList.add('active');
        }

        async function refresh() {
            const res = await fetch('/api/report');
            const data = await res.json();

            if (!data || data.error) {
                document.body.innerHTML = '<div style="text-align:center;margin-top:100px;"><h2 style="color:#ff4444;">⚠️ No Data Found</h2><p style="color:#888;">Run main_scanner.py first, then refresh.</p></div>';
                return;
            }

            const s = data.summary || {};
            const db = data.database_stats || {};

            document.getElementById('timestamp').textContent = 'Last Scan: ' + (data.scan_info?.timestamp ? new Date(data.scan_info.timestamp).toLocaleString() : 'N/A');

            // Stats Grid
            document.getElementById('statsGrid').innerHTML = `
                <div class="stat-card" style="border-left-color:#4a9eff;">
                    <h3>Total Scanned</h3>
                    <div class="value" style="color:#4a9eff;">${s.total_collected || db.total_content || 0}</div>
                    <div class="label">videos + posts + tweets</div>
                </div>
                <div class="stat-card" style="border-left-color:#ff4444;">
                    <h3>Flagged</h3>
                    <div class="value red">${s.total_flagged || 0}</div>
                    <div class="label">MEDIUM / HIGH / CRITICAL</div>
                </div>
                <div class="stat-card" style="border-left-color:#ff8800;">
                    <h3>High+Critical</h3>
                    <div class="value orange">${(s.by_risk?.CRITICAL || 0) + (s.by_risk?.HIGH || 0)}</div>
                    <div class="label">needs immediate attention</div>
                </div>
                <div class="stat-card" style="border-left-color:#ffcc00;">
                    <h3>Unique Phones</h3>
                    <div class="value yellow">${db.unique_phones || 0}</div>
                    <div class="label">extracted from content</div>
                </div>
                <div class="stat-card" style="border-left-color:#00cc44;">
                    <h3>Unique UPI IDs</h3>
                    <div class="value green">${db.unique_upi || 0}</div>
                    <div class="label">payment addresses found</div>
                </div>
                <div class="stat-card" style="border-left-color:#e94560;">
                    <h3>Total in Database</h3>
                    <div class="value" style="color:#e94560;">${db.total_content || s.total_collected || 0}</div>
                    <div class="label">historical records</div>
                </div>
            `;

            // Risk Chart
            const riskCtx = document.getElementById('riskChart').getContext('2d');
            const riskData = {
                labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                datasets: [{
                    data: [
                        s.by_risk?.CRITICAL || 0,
                        s.by_risk?.HIGH || 0,
                        s.by_risk?.MEDIUM || 0,
                        db.total_content ? (db.total_content - (s.total_flagged || 0)) : 0
                    ],
                    backgroundColor: ['#ff4444', '#ff8800', '#ffcc00', '#2a2a4e'],
                    borderWidth: 0
                }]
            };
            if (riskChartInstance) riskChartInstance.destroy();
            riskChartInstance = new Chart(riskCtx, {
                type: 'doughnut',
                data: riskData,
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'bottom', labels: { color: '#aaa' } }
                    }
                }
            });

            // Platform Chart
            const platCtx = document.getElementById('platformChart').getContext('2d');
            const platData = {
                labels: Object.keys(s.by_platform || db.platform_distribution || {}),
                datasets: [{
                    data: Object.values(s.by_platform || db.platform_distribution || {}),
                    backgroundColor: ['#e94560', '#4a9eff', '#ff8800', '#00cc44', '#ffcc00'],
                    borderWidth: 0
                }]
            };
            if (platformChartInstance) platformChartInstance.destroy();
            platformChartInstance = new Chart(platCtx, {
                type: 'bar',
                data: platData,
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, ticks: { color: '#666' } },
                        x: { ticks: { color: '#aaa' } }
                    }
                }
            });

            // Findings Table
            const findings = [...(data.critical_findings || []), ...(data.high_risk_findings || [])];
            document.getElementById('findingsTable').innerHTML = findings.length === 0
                ? '<tr><td colspan="5" style="text-align:center;color:#666;padding:30px;">No critical or high risk findings</td></tr>'
                : findings.slice(0, 50).map(f => `
                    <tr>
                        <td><span class="badge badge-${f.risk_analysis?.risk_level || f.risk_level}">${f.risk_analysis?.risk_level || f.risk_level}</span></td>
                        <td>${f.source || f.platform || 'unknown'}</td>
                        <td>${(f.title || f.caption || f.text || 'No title').substring(0, 60)}</td>
                        <td>${(f.views || f.likes || 0).toLocaleString()}</td>
                        <td><a href="${f.url || '#'}" target="_blank">Open →</a></td>
                    </tr>
                `).join('');

            // Phone Entities
            const topEntities = db.top_entities || [];
            const phones = topEntities.filter(e => e.type === 'phone_numbers').slice(0, 15);
            const upis = topEntities.filter(e => e.type === 'upi_ids').slice(0, 15);
            const emails = topEntities.filter(e => e.type === 'emails').slice(0, 15);

            const telegramUsers = topEntities.filter(
                e => e.type === 'telegram_usernames'
            ).slice(0, 15);

            const domains = topEntities.filter(
                e => e.type === 'domains'
            ).slice(0, 15);

            const wallets = topEntities.filter(
                e =>
                    e.type === 'btc_wallets' ||
                    e.type === 'eth_wallets' ||
                    e.type === 'trx_wallets'
            ).slice(0, 15);

            document.getElementById('phoneEntities').innerHTML = phones.length === 0
                ? '<p style="color:#666;">No phone numbers found</p>'
                : '<div>' + phones.map(e => `<span class="entity-chip phone">📞 ${e.value} (${e.count}x)</span>`).join(' ') + '</div>';

            document.getElementById('upiEntities').innerHTML = upis.length === 0
                ? '<p style="color:#666;">No UPI IDs found</p>'
                : '<div>' + upis.map(e => `<span class="entity-chip upi">💳 ${e.value} (${e.count}x)</span>`).join(' ') + '</div>';

            document.getElementById('emailEntities').innerHTML = emails.length === 0
                ? '<p style="color:#666;">No emails found</p>'
                : '<div>' + emails.map(e => `<span class="entity-chip email">📧 ${e.value} (${e.count}x)</span>`).join(' ') + '</div>';

            document.getElementById('telegramEntities').innerHTML =
                telegramUsers.length === 0
                ? '<p style="color:#666;">No Telegram usernames found</p>'
                : '<div>' + telegramUsers.map(
                    e => `<span class="entity-chip">👤 ${e.value} (${e.count}x)</span>`
                  ).join(' ') + '</div>';

            document.getElementById('domainEntities').innerHTML =
                domains.length === 0
                ? '<p style="color:#666;">No domains found</p>'
                : '<div>' + domains.map(
                    e => `<span class="entity-chip">🌐 ${e.value} (${e.count}x)</span>`
                  ).join(' ') + '</div>';

            document.getElementById('walletEntities').innerHTML =
                wallets.length === 0
                ? '<p style="color:#666;">No wallets found</p>'
                : '<div>' + wallets.map(
                    e => `<span class="entity-chip">₿ ${e.value.substring(0,15)}... (${e.count}x)</span>`
                  ).join(' ') + '</div>';

            // Database Stats
            document.getElementById('dbStats').innerHTML = `
                <div class="stats-grid" style="grid-template-columns: repeat(4, 1fr);">
                    <div class="stat-card" style="border-left-color:#00cc44;">
                        <h3>Total Content</h3>
                        <div class="value" style="color:#00cc44;">${db.total_content || 0}</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#4a9eff;">
                        <h3>Unique Phones</h3>
                        <div class="value" style="color:#4a9eff;">${db.unique_phones || 0}</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#ff8800;">
                        <h3>Unique UPI</h3>
                        <div class="value" style="color:#ff8800;">${db.unique_upi || 0}</div>
                    </div>
                    <div class="stat-card" style="border-left-color:#e94560;">
                        <h3>Scans Run</h3>
                        <div class="value" style="color:#e94560;">${(data.database_stats?.recent_scans || []).length}</div>
                    </div>
                </div>
                <h3 style="color:#aaa;margin-top:20px;">Risk Distribution in Database:</h3>
                <div style="display:flex;gap:20px;margin-top:10px;">
                    ${Object.entries(db.risk_distribution || {}).map(([level, count]) => `
                        <div><span class="badge badge-${level}">${level}: ${count}</span></div>
                    `).join('')}
                </div>
            `;

            // Scan History
            const scanHistory = db.recent_scans || [];
            document.getElementById('scanHistory').innerHTML = scanHistory.length === 0
                ? '<p style="color:#666;">No scan history</p>'
                : '<table><thead><tr><th>Date/Time</th><th>Scanned</th><th>Flagged</th></tr></thead><tbody>' +
                  scanHistory.map(h => `
                    <tr>
                        <td>${new Date(h.time).toLocaleString()}</td>
                        <td>${h.scanned}</td>
                        <td style="color:${h.flagged > 0 ? '#ff4444' : '#00cc44'};">${h.flagged}</td>
                    </tr>
                  `).join('') + '</tbody></table>';

            // IOC Reputation
            const suspiciousIocs = data.database_stats?.suspicious_iocs || [];

            document.getElementById('iocTable').innerHTML =
                suspiciousIocs.length === 0
                ? '<p style="color:#666;">No suspicious IOCs found</p>'
                : `
                <table>
                    <thead>
                        <tr>
                            <th>Entity</th>
                            <th>Type</th>
                            <th>Occurrences</th>
                            <th>Score</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${suspiciousIocs.map(i => `
                            <tr>
                                <td>${i.entity}</td>
                                <td>${i.type}</td>
                                <td>${i.occurrences}</td>
                                <td>${i.score}</td>
                                <td>
                                    <span class="badge badge-${i.severity}">
                                        ${i.severity}
                                    </span>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                `;

            // IOC Relationship Graph
            const graphData = data.database_stats?.graph_data || [];

            const nodes = [];
            const edges = [];

            const seen = new Set();

            graphData.forEach(row => {

                const entity = row[0];
                const type = row[1];
                const platform = row[2];

                if(!seen.has(entity)){
                    nodes.push({
                        id: entity,
                        label: entity,
                        shape: 'dot'
                    });
                    seen.add(entity);
                }

                if(!seen.has(platform)){
                    nodes.push({
                        id: platform,
                        label: platform,
                        shape: 'box'
                    });
                    seen.add(platform);
                }

                edges.push({
                    from: entity,
                    to: platform
                });
            });

            if (nodes.length > 0) {
                new vis.Network(
                    document.getElementById('networkGraph'),
                    {
                        nodes: new vis.DataSet(nodes),
                        edges: new vis.DataSet(edges)
                    },
                    {}
                );
            } else {
                document.getElementById('networkGraph').innerHTML = '<p style="color:#666;padding:20px;">No graph data available</p>';
            }

            // Cross-Platform Links
            const crossPlatform = data.cross_platform?.high_priority || data.cross_platform?.all_groups || [];
            document.getElementById('crossPlatform').innerHTML = crossPlatform.length === 0
                ? '<p style="color:#666;">No cross-platform links found</p>'
                : '<table><thead><tr><th>Entity</th><th>Type</th><th>Platforms</th><th>Risk</th></tr></thead><tbody>' +
                  crossPlatform.slice(0, 20).map(g => `
                    <tr>
                        <td><strong>${g.entity}</strong></td>
                        <td>${g.type || g.entity_type}</td>
                        <td>${(g.platforms || []).join(', ')}</td>
                        <td><span class="badge badge-${g.max_risk}">${g.max_risk}</span></td>
                    </tr>
                  `).join('') + '</tbody></table>';
        }

        refresh();
        setInterval(refresh, 30000); // Auto-refresh every 30 seconds
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/report')
def get_report():
    report = get_latest_report()
    if not report:
        return jsonify({'error': 'No report found'})
    return jsonify(report)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
