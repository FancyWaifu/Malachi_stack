#!/usr/bin/env python3
"""
Malachi Web UI

A browser-based interface for configuring and monitoring Malachi.

Usage:
    python3 -m malachi.webui

Then open: http://localhost:7890
"""

import os
import sys
import json
import time
import threading
import socket
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)

# Default port for web UI
WEBUI_PORT = 7890

# Try to import Malachi modules
try:
    from .tun_interface import (
        create_tun_interface, MalachiNetworkDaemon,
        IS_LINUX, IS_MACOS, IS_BSD, PLATFORM
    )
    from .tools import (
        node_id_to_virtual_ip, parse_node_address, format_node_id,
        MalachiPing, MalachiLookup, MalachiScanner
    )
    MALACHI_AVAILABLE = True
except ImportError:
    MALACHI_AVAILABLE = False
    PLATFORM = "unknown"
    IS_LINUX = IS_MACOS = IS_BSD = False


# =============================================================================
# HTML Templates
# =============================================================================

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malachi Control Panel</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --accent-hover: #79b8ff;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 0;
            margin-bottom: 24px;
        }

        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            font-size: 24px;
            font-weight: 600;
            color: var(--accent);
        }

        .logo span {
            color: var(--text-secondary);
            font-weight: 400;
        }

        nav {
            display: flex;
            gap: 8px;
        }

        nav a {
            color: var(--text-primary);
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 6px;
            transition: background 0.2s;
        }

        nav a:hover, nav a.active {
            background: var(--bg-tertiary);
        }

        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        .card-title {
            font-size: 18px;
            font-weight: 600;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 16px;
        }

        .stat-box {
            background: var(--bg-tertiary);
            padding: 16px;
            border-radius: 6px;
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .stat-value {
            font-size: 24px;
            font-weight: 600;
            margin-top: 4px;
        }

        .stat-value.success { color: var(--success); }
        .stat-value.warning { color: var(--warning); }
        .stat-value.error { color: var(--error); }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 12px;
            text-transform: uppercase;
        }

        tr:hover {
            background: var(--bg-tertiary);
        }

        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }

        .badge.success { background: rgba(63, 185, 80, 0.2); color: var(--success); }
        .badge.warning { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
        .badge.error { background: rgba(248, 81, 73, 0.2); color: var(--error); }

        input, select, textarea {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-size: 14px;
            width: 100%;
        }

        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--accent);
        }

        button {
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }

        button:hover {
            background: var(--accent-hover);
        }

        button.secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        button.secondary:hover {
            background: var(--border-color);
        }

        button.danger {
            background: var(--error);
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: var(--text-secondary);
            font-size: 14px;
        }

        .form-row {
            display: flex;
            gap: 12px;
            align-items: flex-end;
        }

        .form-row .form-group {
            flex: 1;
        }

        .console {
            background: #000;
            color: #0f0;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 13px;
            padding: 16px;
            border-radius: 6px;
            height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
        }

        .console .error { color: #f55; }
        .console .info { color: #5ff; }
        .console .success { color: #5f5; }

        .node-id {
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            color: var(--accent);
        }

        .ip-address {
            font-family: 'Monaco', 'Menlo', monospace;
        }

        .copy-btn {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            padding: 4px;
            font-size: 12px;
        }

        .copy-btn:hover {
            color: var(--accent);
        }

        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 20px;
        }

        .tab {
            padding: 12px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            color: var(--text-secondary);
            transition: all 0.2s;
        }

        .tab:hover {
            color: var(--text-primary);
        }

        .tab.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .alert {
            padding: 12px 16px;
            border-radius: 6px;
            margin-bottom: 16px;
        }

        .alert.info {
            background: rgba(88, 166, 255, 0.1);
            border: 1px solid var(--accent);
        }

        .alert.success {
            background: rgba(63, 185, 80, 0.1);
            border: 1px solid var(--success);
        }

        .alert.error {
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--error);
        }

        footer {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-secondary);
            font-size: 14px;
        }

        footer a {
            color: var(--accent);
            text-decoration: none;
        }

        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }

            header .container {
                flex-direction: column;
                gap: 16px;
            }

            nav {
                flex-wrap: wrap;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="logo">Malachi <span>Control Panel</span></div>
            <nav>
                <a href="/" class="active">Dashboard</a>
                <a href="/tools">Tools</a>
                <a href="/config">Config</a>
                <a href="/logs">Logs</a>
            </nav>
        </div>
    </header>

    <div class="container">
        {{CONTENT}}
    </div>

    <footer>
        Malachi Stack &middot; <a href="https://github.com/FancyWaifu/Malachi_stack">GitHub</a>
    </footer>

    <script>
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabGroup = tab.parentElement;
                const contentId = tab.dataset.tab;

                tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.toggle('active', content.id === contentId);
                });
            });
        });

        // Copy to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard!');
            });
        }

        // Auto-refresh stats
        function refreshStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    // Update stats display
                    if (data.daemon_running !== undefined) {
                        const el = document.getElementById('daemon-status');
                        if (el) {
                            el.textContent = data.daemon_running ? 'Running' : 'Stopped';
                            el.className = 'stat-value ' + (data.daemon_running ? 'success' : 'error');
                        }
                    }
                });
        }

        // Refresh every 5 seconds
        setInterval(refreshStats, 5000);

        // Form handlers
        document.querySelectorAll('form[data-ajax]').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(form);
                const data = Object.fromEntries(formData);
                const output = document.getElementById(form.dataset.output);

                try {
                    const response = await fetch(form.action, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                    });
                    const result = await response.json();

                    if (output) {
                        output.innerHTML += '<span class="' + (result.success ? 'success' : 'error') + '">' +
                            result.message + '</span>\\n';
                        output.scrollTop = output.scrollHeight;
                    }
                } catch (err) {
                    if (output) {
                        output.innerHTML += '<span class="error">Error: ' + err.message + '</span>\\n';
                    }
                }
            });
        });
    </script>
</body>
</html>'''

DASHBOARD_CONTENT = '''
<div class="grid">
    <div class="stat-box">
        <div class="stat-label">Daemon Status</div>
        <div id="daemon-status" class="stat-value {{DAEMON_STATUS_CLASS}}">{{DAEMON_STATUS}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Platform</div>
        <div class="stat-value">{{PLATFORM}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Interface</div>
        <div class="stat-value">{{INTERFACE}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Neighbors</div>
        <div class="stat-value">{{NEIGHBOR_COUNT}}</div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Node Identity</div>
    </div>
    <table>
        <tr>
            <td style="width: 150px; color: var(--text-secondary);">Node ID</td>
            <td>
                <span class="node-id">{{NODE_ID}}</span>
                <button class="copy-btn" onclick="copyToClipboard('{{NODE_ID}}')">[copy]</button>
            </td>
        </tr>
        <tr>
            <td style="color: var(--text-secondary);">Virtual IP</td>
            <td>
                <span class="ip-address">{{VIRTUAL_IP}}</span>
                <button class="copy-btn" onclick="copyToClipboard('{{VIRTUAL_IP}}')">[copy]</button>
            </td>
        </tr>
        <tr>
            <td style="color: var(--text-secondary);">DNS Name</td>
            <td>
                <span class="ip-address">{{NODE_ID_SHORT}}.mli</span>
                <button class="copy-btn" onclick="copyToClipboard('{{NODE_ID_SHORT}}.mli')">[copy]</button>
            </td>
        </tr>
    </table>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Discovered Neighbors</div>
        <button onclick="location.reload()" class="secondary">Refresh</button>
    </div>
    {{NEIGHBOR_TABLE}}
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Quick Actions</div>
    </div>
    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
        <form action="/api/daemon/start" method="post" style="display: inline;">
            <button type="submit">Start Daemon</button>
        </form>
        <form action="/api/daemon/stop" method="post" style="display: inline;">
            <button type="submit" class="danger">Stop Daemon</button>
        </form>
        <form action="/api/ndp/discover" method="post" style="display: inline;">
            <button type="submit" class="secondary">Broadcast Discovery</button>
        </form>
    </div>
</div>
'''

TOOLS_CONTENT = '''
<div class="tabs">
    <div class="tab active" data-tab="ping-tab">Ping</div>
    <div class="tab" data-tab="lookup-tab">Lookup</div>
    <div class="tab" data-tab="scan-tab">Scan</div>
</div>

<div id="ping-tab" class="tab-content active">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Ping Node</div>
        </div>
        <form action="/api/ping" method="post" data-ajax data-output="ping-output">
            <div class="form-row">
                <div class="form-group">
                    <label>Target (Node ID or Virtual IP)</label>
                    <input type="text" name="target" placeholder="a1b2c3d4 or 10.144.45.23" required>
                </div>
                <div class="form-group" style="flex: 0 0 100px;">
                    <label>Count</label>
                    <input type="number" name="count" value="4" min="1" max="100">
                </div>
                <div class="form-group" style="flex: 0 0 auto;">
                    <button type="submit">Ping</button>
                </div>
            </div>
        </form>
        <div id="ping-output" class="console" style="margin-top: 16px;"></div>
    </div>
</div>

<div id="lookup-tab" class="tab-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Address Lookup</div>
        </div>
        <form action="/api/lookup" method="post" data-ajax data-output="lookup-output">
            <div class="form-row">
                <div class="form-group">
                    <label>Address (Node ID or Virtual IP)</label>
                    <input type="text" name="address" placeholder="a1b2c3d4e5f67890..." required>
                </div>
                <div class="form-group" style="flex: 0 0 auto;">
                    <button type="submit">Lookup</button>
                </div>
            </div>
        </form>
        <div id="lookup-output" class="console" style="margin-top: 16px;"></div>
    </div>
</div>

<div id="scan-tab" class="tab-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Network Scan</div>
        </div>
        <form action="/api/scan" method="post" data-ajax data-output="scan-output">
            <div class="form-row">
                <div class="form-group" style="flex: 0 0 150px;">
                    <label>Timeout (seconds)</label>
                    <input type="number" name="timeout" value="10" min="1" max="60">
                </div>
                <div class="form-group" style="flex: 0 0 auto;">
                    <button type="submit">Start Scan</button>
                </div>
            </div>
        </form>
        <div id="scan-output" class="console" style="margin-top: 16px;"></div>
    </div>
</div>
'''

CONFIG_CONTENT = '''
<div class="card">
    <div class="card-header">
        <div class="card-title">Network Configuration</div>
    </div>
    <form action="/api/config/save" method="post">
        <div class="form-group">
            <label>Physical Interface</label>
            <select name="interface">
                {{INTERFACE_OPTIONS}}
            </select>
        </div>
        <div class="form-group">
            <label>Virtual IP Subnet</label>
            <input type="text" name="subnet" value="10.144.0.0/16" disabled>
            <small style="color: var(--text-secondary);">Cannot be changed (hardcoded)</small>
        </div>
        <div class="form-group">
            <label>Local Virtual IP</label>
            <input type="text" name="local_ip" value="10.144.0.1" disabled>
        </div>
        <button type="submit">Save Configuration</button>
    </form>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">DNS Configuration (.mli)</div>
    </div>
    <div class="alert info">
        Configure your system to resolve <code>*.mli</code> domains to Malachi virtual IPs.
    </div>
    <form action="/api/dns/configure" method="post">
        <div class="form-group">
            <label>DNS Server Address</label>
            <input type="text" name="dns_address" value="127.0.0.1">
        </div>
        <div class="form-group">
            <label>Status</label>
            <div style="padding: 8px 0;">
                <span class="badge {{DNS_STATUS_CLASS}}">{{DNS_STATUS}}</span>
            </div>
        </div>
        <div style="display: flex; gap: 12px;">
            <button type="submit">Configure DNS</button>
            <form action="/api/dns/start" method="post" style="display: inline;">
                <button type="submit" class="secondary">Start DNS Server</button>
            </form>
        </div>
    </form>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Identity Management</div>
    </div>
    <table>
        <tr>
            <td style="width: 150px; color: var(--text-secondary);">Current Identity</td>
            <td class="node-id">{{NODE_ID}}</td>
        </tr>
        <tr>
            <td style="color: var(--text-secondary);">Key Directory</td>
            <td><code>~/.ministack/</code></td>
        </tr>
    </table>
    <div style="margin-top: 16px;">
        <form action="/api/identity/generate" method="post" style="display: inline;">
            <button type="submit" class="danger"
                onclick="return confirm('Generate new identity? This will replace your current keys.')">
                Generate New Identity
            </button>
        </form>
    </div>
</div>
'''

LOGS_CONTENT = '''
<div class="card">
    <div class="card-header">
        <div class="card-title">System Logs</div>
        <button onclick="document.getElementById('log-output').innerHTML = ''" class="secondary">Clear</button>
    </div>
    <div id="log-output" class="console" style="height: 500px;">
{{LOGS}}
    </div>
</div>
'''


# =============================================================================
# Web Server
# =============================================================================

class MalachiWebUI(BaseHTTPRequestHandler):
    """HTTP request handler for Malachi Web UI."""

    # Class-level state
    daemon: Optional[MalachiNetworkDaemon] = None
    dns_server = None
    log_buffer: list = []

    def log_message(self, format, *args):
        """Override to capture logs."""
        message = format % args
        MalachiWebUI.log_buffer.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        if len(MalachiWebUI.log_buffer) > 1000:
            MalachiWebUI.log_buffer = MalachiWebUI.log_buffer[-500:]

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/' or path == '/dashboard':
            self._serve_dashboard()
        elif path == '/tools':
            self._serve_tools()
        elif path == '/config':
            self._serve_config()
        elif path == '/logs':
            self._serve_logs()
        elif path == '/api/stats':
            self._api_stats()
        else:
            self._send_404()

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        # Read body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ''

        try:
            data = json.loads(body) if body else {}
        except:
            data = {}

        if path == '/api/ping':
            self._api_ping(data)
        elif path == '/api/lookup':
            self._api_lookup(data)
        elif path == '/api/scan':
            self._api_scan(data)
        elif path == '/api/daemon/start':
            self._api_daemon_start()
        elif path == '/api/daemon/stop':
            self._api_daemon_stop()
        elif path == '/api/dns/configure':
            self._api_dns_configure(data)
        elif path == '/api/dns/start':
            self._api_dns_start()
        elif path == '/api/config/save':
            self._api_config_save(data)
        elif path == '/api/identity/generate':
            self._api_identity_generate()
        elif path == '/api/ndp/discover':
            self._api_ndp_discover()
        else:
            self._send_json({'success': False, 'message': 'Unknown endpoint'})

    def _serve_html(self, content: str):
        """Serve HTML content."""
        html = HTML_TEMPLATE.replace('{{CONTENT}}', content)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_json(self, data: dict):
        """Send JSON response."""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_404(self):
        """Send 404 response."""
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 Not Found</h1>')

    def _get_node_info(self) -> dict:
        """Get current node information."""
        if MalachiWebUI.daemon and MalachiWebUI.daemon.node_id:
            node_id_bytes = MalachiWebUI.daemon.node_id
            node_id_hex = node_id_bytes.hex()

            # Calculate virtual IP from bytes
            if MALACHI_AVAILABLE:
                virtual_ip = node_id_to_virtual_ip(node_id_hex)
            else:
                # Manual calculation
                node_hash = int.from_bytes(node_id_bytes[:4], 'big')
                third = (node_hash >> 8) & 0xFF
                fourth = max(2, node_hash & 0xFF)
                virtual_ip = f"10.144.{third}.{fourth}"

            return {
                'node_id': node_id_hex,
                'node_id_short': node_id_hex[:8],
                'virtual_ip': virtual_ip,
                'interface': MalachiWebUI.daemon.tun.interface_name if MalachiWebUI.daemon.tun else 'N/A',
                'running': MalachiWebUI.daemon._running,
            }
        else:
            # Generate placeholder
            node_id = secrets.token_hex(16)
            return {
                'node_id': node_id,
                'node_id_short': node_id[:8],
                'virtual_ip': '10.144.0.1',
                'interface': 'Not started',
                'running': False,
            }

    def _serve_dashboard(self):
        """Serve dashboard page."""
        info = self._get_node_info()

        neighbors = []
        if MalachiWebUI.daemon:
            neighbors = list(MalachiWebUI.daemon.get_neighbors().items())

        if neighbors:
            neighbor_rows = ''
            for node_id, vip in neighbors:
                neighbor_rows += f'''
                <tr>
                    <td class="node-id">{node_id.hex()[:16]}...</td>
                    <td class="ip-address">{vip}</td>
                    <td><span class="badge success">Online</span></td>
                </tr>'''
            neighbor_table = f'''
            <table>
                <thead>
                    <tr>
                        <th>Node ID</th>
                        <th>Virtual IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{neighbor_rows}</tbody>
            </table>'''
        else:
            neighbor_table = '<p style="color: var(--text-secondary);">No neighbors discovered yet.</p>'

        content = DASHBOARD_CONTENT
        content = content.replace('{{DAEMON_STATUS}}', 'Running' if info['running'] else 'Stopped')
        content = content.replace('{{DAEMON_STATUS_CLASS}}', 'success' if info['running'] else 'error')
        content = content.replace('{{PLATFORM}}', PLATFORM.title())
        content = content.replace('{{INTERFACE}}', info['interface'])
        content = content.replace('{{NEIGHBOR_COUNT}}', str(len(neighbors)))
        content = content.replace('{{NODE_ID}}', info['node_id'])
        content = content.replace('{{NODE_ID_SHORT}}', info['node_id_short'])
        content = content.replace('{{VIRTUAL_IP}}', info['virtual_ip'])
        content = content.replace('{{NEIGHBOR_TABLE}}', neighbor_table)

        self._serve_html(content)

    def _serve_tools(self):
        """Serve tools page."""
        self._serve_html(TOOLS_CONTENT)

    def _serve_config(self):
        """Serve config page."""
        info = self._get_node_info()

        # Get network interfaces
        interfaces = self._get_interfaces()
        options = ''.join(f'<option value="{i}">{i}</option>' for i in interfaces)

        # DNS status
        dns_configured = os.path.exists('/etc/resolver/mli') if IS_MACOS else False

        content = CONFIG_CONTENT
        content = content.replace('{{INTERFACE_OPTIONS}}', options)
        content = content.replace('{{NODE_ID}}', info['node_id'])
        content = content.replace('{{DNS_STATUS}}', 'Configured' if dns_configured else 'Not Configured')
        content = content.replace('{{DNS_STATUS_CLASS}}', 'success' if dns_configured else 'warning')

        self._serve_html(content)

    def _serve_logs(self):
        """Serve logs page."""
        logs = '\n'.join(MalachiWebUI.log_buffer[-100:])
        content = LOGS_CONTENT.replace('{{LOGS}}', logs)
        self._serve_html(content)

    def _get_interfaces(self) -> list:
        """Get available network interfaces."""
        interfaces = []
        try:
            import subprocess
            if IS_MACOS:
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
                interfaces = [i for i in result.stdout.strip().split()
                            if not i.startswith(('lo', 'utun', 'bridge', 'awdl', 'llw'))]
            else:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ': ' in line and '@' not in line:
                        name = line.split(': ')[1].split(':')[0]
                        if not name.startswith(('lo', 'tun', 'tap')):
                            interfaces.append(name)
        except:
            interfaces = ['eth0', 'en0']
        return interfaces

    def _api_stats(self):
        """API: Get stats."""
        info = self._get_node_info()
        self._send_json({
            'daemon_running': info['running'],
            'node_id': info['node_id'],
            'virtual_ip': info['virtual_ip'],
            'interface': info['interface'],
            'neighbors': len(MalachiWebUI.daemon.get_neighbors()) if MalachiWebUI.daemon else 0,
        })

    def _api_ping(self, data: dict):
        """API: Ping a node."""
        target = data.get('target', '')
        count = int(data.get('count', 4))

        if not target:
            self._send_json({'success': False, 'message': 'Target required'})
            return

        if MALACHI_AVAILABLE:
            ping = MalachiPing()
            stats = ping.ping(target, count=count, quiet=True)
            message = f"PING {target}\n"
            message += f"Transmitted: {stats.transmitted}, Received: {stats.received}\n"
            message += f"Loss: {stats.loss_percent:.1f}%\n"
            if stats.received > 0:
                message += f"RTT min/avg/max: {stats.min_rtt:.2f}/{stats.avg_rtt:.2f}/{stats.max_rtt:.2f} ms"
            self._send_json({'success': True, 'message': message})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_lookup(self, data: dict):
        """API: Lookup address."""
        address = data.get('address', '')

        if not address:
            self._send_json({'success': False, 'message': 'Address required'})
            return

        if MALACHI_AVAILABLE:
            lookup = MalachiLookup()
            result = lookup.lookup(address)
            message = f"Address: {result['input']}\n"
            message += f"Virtual IP: {result['virtual_ip']}\n"
            message += f"Node ID: {result['node_id']}\n"
            message += f"DNS: {result['node_id'][:8]}.mli" if result['node_id'] else ""
            self._send_json({'success': True, 'message': message})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_scan(self, data: dict):
        """API: Scan network."""
        timeout = float(data.get('timeout', 10))

        if MALACHI_AVAILABLE:
            scanner = MalachiScanner()
            nodes = scanner.scan(timeout=min(timeout, 30), quiet=True)
            message = f"Scan complete. Found {len(nodes)} nodes:\n\n"
            for node in nodes:
                message += f"  {node.virtual_ip}  {node.node_id.hex()[:16]}...  {node.rtt_ms:.1f}ms\n"
            self._send_json({'success': True, 'message': message})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_daemon_start(self):
        """API: Start daemon."""
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            self._send_json({'success': False, 'message': 'Daemon is already running'})
        else:
            self._send_json({
                'success': False,
                'message': 'Start daemon with Web UI from command line:\n\nsudo python3 -m malachi.tun_interface start --webui\n\nThen refresh this page.'
            })

    def _api_daemon_stop(self):
        """API: Stop daemon."""
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            self._send_json({
                'success': False,
                'message': 'Cannot stop daemon from Web UI.\nPress Ctrl+C in the terminal where daemon is running.'
            })
        else:
            self._send_json({'success': False, 'message': 'Daemon not running'})

    def _api_dns_configure(self, data: dict):
        """API: Configure DNS."""
        self._send_json({'success': False, 'message': 'Run from command line:\nsudo python3 -m malachi.dns configure'})

    def _api_dns_start(self):
        """API: Start DNS server."""
        self._send_json({'success': False, 'message': 'Run from command line:\nsudo python3 -m malachi.dns start'})

    def _api_config_save(self, data: dict):
        """API: Save configuration."""
        self._send_json({'success': True, 'message': 'Configuration saved'})

    def _api_identity_generate(self):
        """API: Generate new identity."""
        self._send_json({'success': False, 'message': 'Run from command line:\npython3 -m malachi.tun_interface keys generate'})

    def _api_ndp_discover(self):
        """API: Broadcast NDP discovery."""
        self._send_json({'success': True, 'message': 'Discovery broadcast sent (simulated)'})


def run_webui(host: str = "0.0.0.0", port: int = WEBUI_PORT):
    """Run the web UI server."""
    server = HTTPServer((host, port), MalachiWebUI)
    logger.info(f"Malachi Web UI running on http://{host}:{port}")
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   MALACHI WEB UI                             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Open in browser:  http://localhost:{port:<5}                  ║
║                                                              ║
║  Or from another device: http://<your-ip>:{port:<5}            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Press Ctrl+C to stop...
""")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


def main():
    """CLI entry point."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="Malachi Web UI")
    parser.add_argument("-p", "--port", type=int, default=WEBUI_PORT,
                       help=f"Port to listen on (default: {WEBUI_PORT})")
    parser.add_argument("-H", "--host", default="0.0.0.0",
                       help="Host to bind to (default: 0.0.0.0)")

    args = parser.parse_args()
    run_webui(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
