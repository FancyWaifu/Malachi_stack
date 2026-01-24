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

        /* Toast notifications */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .toast {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px 20px;
            min-width: 300px;
            max-width: 450px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
            animation: slideIn 0.3s ease;
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }

        .toast.success { border-left: 4px solid var(--success); }
        .toast.error { border-left: 4px solid var(--error); }
        .toast.info { border-left: 4px solid var(--accent); }

        .toast-icon {
            font-size: 18px;
            flex-shrink: 0;
        }

        .toast.success .toast-icon { color: var(--success); }
        .toast.error .toast-icon { color: var(--error); }
        .toast.info .toast-icon { color: var(--accent); }

        .toast-content {
            flex: 1;
        }

        .toast-title {
            font-weight: 600;
            margin-bottom: 4px;
        }

        .toast-message {
            color: var(--text-secondary);
            font-size: 14px;
            white-space: pre-wrap;
        }

        .toast-close {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 18px;
            padding: 0;
            line-height: 1;
        }

        .toast-close:hover {
            color: var(--text-primary);
        }

        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
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

            .toast-container {
                left: 10px;
                right: 10px;
            }

            .toast {
                min-width: auto;
            }
        }
    </style>
</head>
<body>
    <div id="toast-container" class="toast-container"></div>

    <header>
        <div class="container">
            <div class="logo">Malachi <span>Control Panel</span></div>
            <nav>
                <a href="/" class="active">Dashboard</a>
                <a href="/mesh">Mesh</a>
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
        // Toast notification system
        function showToast(type, title, message, duration = 5000) {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;

            const icons = {
                success: '&#10003;',
                error: '&#10007;',
                info: '&#9432;'
            };

            toast.innerHTML =
                '<span class="toast-icon">' + icons[type] + '</span>' +
                '<div class="toast-content">' +
                    '<div class="toast-title">' + title + '</div>' +
                    '<div class="toast-message">' + message + '</div>' +
                '</div>' +
                '<button class="toast-close" onclick="closeToast(this.parentElement)">&times;</button>';

            container.appendChild(toast);

            // Auto-remove after duration
            if (duration > 0) {
                setTimeout(() => closeToast(toast), duration);
            }

            return toast;
        }

        function closeToast(toast) {
            if (!toast || !toast.parentElement) return;
            toast.style.animation = 'slideOut 0.3s ease forwards';
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.parentElement.removeChild(toast);
                }
            }, 300);
        }

        // API action handler
        async function apiAction(endpoint, loadingMessage, data = {}) {
            const loadingToast = showToast('info', 'Processing', loadingMessage, 0);

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
                const result = await response.json();

                closeToast(loadingToast);

                if (result.success) {
                    showToast('success', 'Success', result.message);
                    // Refresh stats after successful action
                    setTimeout(refreshStats, 500);
                } else {
                    showToast('error', 'Error', result.message, 8000);
                }
            } catch (err) {
                closeToast(loadingToast);
                showToast('error', 'Network Error', err.message);
            }
        }

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
                showToast('success', 'Copied', 'Text copied to clipboard');
            }).catch(() => {
                showToast('error', 'Failed', 'Could not copy to clipboard');
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
                })
                .catch(() => {}); // Silently fail on network errors
        }

        // Refresh every 5 seconds
        setInterval(refreshStats, 5000);

        // Form handlers for tools (ping, lookup, scan)
        document.querySelectorAll('form[data-ajax]').forEach(form => {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = new FormData(form);
                const data = Object.fromEntries(formData);
                const output = document.getElementById(form.dataset.output);
                const submitBtn = form.querySelector('button[type="submit"]');
                const originalText = submitBtn.textContent;

                // Disable button and show loading
                submitBtn.disabled = true;
                submitBtn.textContent = 'Running...';

                try {
                    const response = await fetch(form.action, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(data)
                    });
                    const result = await response.json();

                    if (output) {
                        const timestamp = new Date().toLocaleTimeString();
                        output.innerHTML += '<span class="info">[' + timestamp + ']</span> ';
                        output.innerHTML += '<span class="' + (result.success ? 'success' : 'error') + '">' +
                            result.message + '</span>\\n\\n';
                        output.scrollTop = output.scrollHeight;
                    }
                } catch (err) {
                    if (output) {
                        output.innerHTML += '<span class="error">Error: ' + err.message + '</span>\\n\\n';
                    }
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = originalText;
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
        <div class="stat-label">Connections</div>
        <div class="stat-value">{{NEIGHBOR_COUNT}}</div>
        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            {{DIRECT_COUNT}} direct, {{RELAY_COUNT}} relayed
        </div>
    </div>
</div>

<div class="grid" style="margin-top: 16px;">
    <div class="stat-box">
        <div class="stat-label">DHT Peers</div>
        <div class="stat-value">{{DHT_PEERS}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Services</div>
        <div class="stat-value">{{SERVICES_COUNT}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Packets In/Out</div>
        <div class="stat-value" style="font-size: 18px;">{{PACKETS_IN}} / {{PACKETS_OUT}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Forwarded</div>
        <div class="stat-value">{{FORWARDED}}</div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Network Topology</div>
        <button onclick="refreshTopology()" class="secondary">Refresh</button>
    </div>
    <div id="topology-container" style="position: relative; height: 350px; background: var(--bg-tertiary); border-radius: 6px; overflow: hidden;">
        <canvas id="topology-canvas" style="width: 100%; height: 100%;"></canvas>
        <div id="topology-legend" style="position: absolute; bottom: 10px; left: 10px; font-size: 12px; color: var(--text-secondary);">
            <span style="color: var(--accent);">●</span> You &nbsp;
            <span style="color: var(--success);">●</span> Direct &nbsp;
            <span style="color: var(--warning);">●</span> Relayed
        </div>
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
        <div class="card-title">Route Table</div>
        <button onclick="location.reload()" class="secondary">Refresh</button>
    </div>
    {{ROUTE_TABLE}}
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">Quick Actions</div>
    </div>
    <div style="display: flex; gap: 12px; flex-wrap: wrap;">
        <button onclick="apiAction('/api/daemon/start', 'Starting daemon...')">Start Daemon</button>
        <button onclick="apiAction('/api/daemon/stop', 'Stopping daemon...')" class="danger">Stop Daemon</button>
        <button onclick="apiAction('/api/ndp/discover', 'Broadcasting...')" class="secondary">Broadcast Discovery</button>
    </div>
</div>

<script>
// Network topology visualization
let topologyData = {{TOPOLOGY_JSON}};

function drawTopology() {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return;

    const container = canvas.parentElement;
    canvas.width = container.clientWidth * 2;
    canvas.height = container.clientHeight * 2;
    canvas.style.width = container.clientWidth + 'px';
    canvas.style.height = container.clientHeight + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(2, 2); // For retina displays

    const width = container.clientWidth;
    const height = container.clientHeight;
    const centerX = width / 2;
    const centerY = height / 2;

    // Clear canvas
    ctx.fillStyle = '#21262d';
    ctx.fillRect(0, 0, width, height);

    const nodes = topologyData.nodes || [];
    const edges = topologyData.edges || [];

    if (nodes.length === 0) {
        ctx.fillStyle = '#8b949e';
        ctx.font = '14px -apple-system, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No connections yet', centerX, centerY);
        ctx.fillText('Start the daemon and discover neighbors', centerX, centerY + 20);
        return;
    }

    // Position nodes in a circle around center
    const nodePositions = {};
    const selfNode = nodes.find(n => n.is_self);
    const otherNodes = nodes.filter(n => !n.is_self);

    // Self at center
    if (selfNode) {
        nodePositions[selfNode.id] = { x: centerX, y: centerY };
    }

    // Others in a circle
    const radius = Math.min(width, height) * 0.35;
    otherNodes.forEach((node, i) => {
        const angle = (2 * Math.PI * i / otherNodes.length) - Math.PI / 2;
        nodePositions[node.id] = {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle)
        };
    });

    // Draw edges
    edges.forEach(edge => {
        const from = nodePositions[edge.from];
        const to = nodePositions[edge.to];
        if (!from || !to) return;

        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.strokeStyle = edge.type === 'direct' ? '#3fb950' : '#d29922';
        ctx.lineWidth = edge.type === 'direct' ? 2 : 1;
        if (edge.type !== 'direct') {
            ctx.setLineDash([5, 5]);
        } else {
            ctx.setLineDash([]);
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // Draw latency label on edge
        if (edge.latency_ms) {
            const midX = (from.x + to.x) / 2;
            const midY = (from.y + to.y) / 2;
            ctx.fillStyle = '#8b949e';
            ctx.font = '10px -apple-system, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(edge.latency_ms.toFixed(0) + 'ms', midX, midY - 5);
        }
    });

    // Draw nodes
    nodes.forEach(node => {
        const pos = nodePositions[node.id];
        if (!pos) return;

        const nodeRadius = node.is_self ? 30 : 25;

        // Node circle
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, nodeRadius, 0, 2 * Math.PI);
        if (node.is_self) {
            ctx.fillStyle = '#58a6ff';
        } else if (node.type === 'direct') {
            ctx.fillStyle = '#238636';
        } else {
            ctx.fillStyle = '#9e6a03';
        }
        ctx.fill();
        ctx.strokeStyle = '#30363d';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Node label
        ctx.fillStyle = '#ffffff';
        ctx.font = node.is_self ? 'bold 11px -apple-system, sans-serif' : '10px -apple-system, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        if (node.is_self) {
            ctx.fillText('YOU', pos.x, pos.y - 5);
            ctx.font = '9px -apple-system, sans-serif';
            ctx.fillText(node.virtual_ip, pos.x, pos.y + 8);
        } else {
            ctx.fillText(node.id.substring(0, 8), pos.x, pos.y - 5);
            ctx.font = '9px -apple-system, sans-serif';
            ctx.fillStyle = '#c9d1d9';
            ctx.fillText(node.virtual_ip, pos.x, pos.y + 8);
        }

        // Hop count badge for non-direct
        if (!node.is_self && node.hop_count > 1) {
            ctx.beginPath();
            ctx.arc(pos.x + nodeRadius - 5, pos.y - nodeRadius + 5, 10, 0, 2 * Math.PI);
            ctx.fillStyle = '#d29922';
            ctx.fill();
            ctx.fillStyle = '#ffffff';
            ctx.font = 'bold 9px -apple-system, sans-serif';
            ctx.fillText(node.hop_count + 'h', pos.x + nodeRadius - 5, pos.y - nodeRadius + 6);
        }
    });
}

function refreshTopology() {
    fetch('/api/topology')
        .then(r => r.json())
        .then(data => {
            topologyData = data;
            drawTopology();
        })
        .catch(() => {});
}

// Draw on load and resize
window.addEventListener('load', drawTopology);
window.addEventListener('resize', drawTopology);

// Auto-refresh topology every 10 seconds
setInterval(refreshTopology, 10000);
</script>
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
    <div class="form-group">
        <label>Physical Interface</label>
        <select name="interface" id="config-interface">
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
    <button onclick="apiAction('/api/config/save', 'Saving...', {interface: document.getElementById('config-interface').value})">Save Configuration</button>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">DNS Configuration (.mli)</div>
    </div>
    <div class="alert info">
        Configure your system to resolve <code>*.mli</code> domains to Malachi virtual IPs.
    </div>
    <div class="form-group">
        <label>DNS Server Address</label>
        <input type="text" id="dns-address" value="127.0.0.1">
    </div>
    <div class="form-group">
        <label>Status</label>
        <div style="padding: 8px 0;">
            <span class="badge {{DNS_STATUS_CLASS}}">{{DNS_STATUS}}</span>
        </div>
    </div>
    <div style="display: flex; gap: 12px;">
        <button onclick="apiAction('/api/dns/configure', 'Configuring DNS...', {dns_address: document.getElementById('dns-address').value})">Configure DNS</button>
        <button onclick="apiAction('/api/dns/start', 'Starting DNS...')" class="secondary">Start DNS Server</button>
    </div>
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
        <button class="danger" onclick="if(confirm('Generate new identity? This will replace your current keys.')) apiAction('/api/identity/generate', 'Generating...')">
            Generate New Identity
        </button>
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

MESH_CONTENT = '''
<div class="grid">
    <div class="stat-box">
        <div class="stat-label">DHT Peers</div>
        <div class="stat-value">{{DHT_PEER_COUNT}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Services</div>
        <div class="stat-value">{{SERVICE_COUNT}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Packets Sent</div>
        <div class="stat-value">{{PACKETS_SENT}}</div>
    </div>
    <div class="stat-box">
        <div class="stat-label">Packets Received</div>
        <div class="stat-value">{{PACKETS_RECEIVED}}</div>
    </div>
</div>

<div class="tabs">
    <div class="tab active" data-tab="peers-tab">DHT Peers</div>
    <div class="tab" data-tab="services-tab">Services</div>
    <div class="tab" data-tab="files-tab">File Transfer</div>
    <div class="tab" data-tab="stats-tab">Statistics</div>
</div>

<div id="peers-tab" class="tab-content active">
    <div class="card">
        <div class="card-header">
            <div class="card-title">DHT Routing Table</div>
            <button onclick="refreshPeers()" class="secondary">Refresh</button>
        </div>
        <div id="peers-table">
            {{PEERS_TABLE}}
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">Bootstrap Nodes</div>
        </div>
        <form id="bootstrap-form" onsubmit="addBootstrap(event)">
            <div class="form-row">
                <div class="form-group">
                    <label>Bootstrap Node Address</label>
                    <input type="text" id="bootstrap-addr" placeholder="hostname:port or IP:port" required>
                </div>
                <div class="form-group" style="flex: 0 0 auto;">
                    <button type="submit">Add</button>
                </div>
            </div>
        </form>
        <div id="bootstrap-list" style="margin-top: 12px;">
            {{BOOTSTRAP_LIST}}
        </div>
    </div>
</div>

<div id="services-tab" class="tab-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Register Service</div>
        </div>
        <form id="service-form" onsubmit="registerService(event)">
            <div class="form-row">
                <div class="form-group">
                    <label>Service Type</label>
                    <select id="service-type">
                        <option value="http">HTTP</option>
                        <option value="ssh">SSH</option>
                        <option value="ftp">FTP</option>
                        <option value="custom">Custom</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Port</label>
                    <input type="number" id="service-port" placeholder="8080" required>
                </div>
                <div class="form-group" style="flex: 0 0 auto;">
                    <button type="submit">Register</button>
                </div>
            </div>
        </form>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">Discovered Services</div>
            <button onclick="refreshServices()" class="secondary">Refresh</button>
        </div>
        <div id="services-table">
            {{SERVICES_TABLE}}
        </div>
    </div>
</div>

<div id="files-tab" class="tab-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Send File</div>
        </div>
        <form id="file-form" onsubmit="sendFile(event)">
            <div class="form-group">
                <label>Destination Node ID</label>
                <input type="text" id="file-dest" placeholder="Node ID or *.mli address" required>
            </div>
            <div class="form-group">
                <label>File Path</label>
                <input type="text" id="file-path" placeholder="/path/to/file" required>
            </div>
            <button type="submit">Send File</button>
        </form>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">Active Transfers</div>
            <button onclick="refreshTransfers()" class="secondary">Refresh</button>
        </div>
        <div id="transfers-table">
            {{TRANSFERS_TABLE}}
        </div>
    </div>
</div>

<div id="stats-tab" class="tab-content">
    <div class="card">
        <div class="card-header">
            <div class="card-title">Network Statistics</div>
            <button onclick="refreshStats()" class="secondary">Refresh</button>
        </div>
        <div class="grid" style="margin-bottom: 20px;">
            <div class="stat-box">
                <div class="stat-label">Bytes Sent</div>
                <div class="stat-value" id="stat-bytes-sent">{{BYTES_SENT}}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Bytes Received</div>
                <div class="stat-value" id="stat-bytes-recv">{{BYTES_RECEIVED}}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Packets Forwarded</div>
                <div class="stat-value" id="stat-forwarded">{{PACKETS_FORWARDED}}</div>
            </div>
            <div class="stat-box">
                <div class="stat-label">Messages Acked</div>
                <div class="stat-value" id="stat-acked">{{MESSAGES_ACKED}}</div>
            </div>
        </div>

        <h4 style="margin-bottom: 12px; color: var(--text-secondary);">Gossip Protocol</h4>
        <table>
            <tr>
                <td style="width: 200px; color: var(--text-secondary);">Messages Sent</td>
                <td id="gossip-sent">{{GOSSIP_SENT}}</td>
            </tr>
            <tr>
                <td style="color: var(--text-secondary);">Messages Received</td>
                <td id="gossip-recv">{{GOSSIP_RECEIVED}}</td>
            </tr>
            <tr>
                <td style="color: var(--text-secondary);">Unique Messages</td>
                <td id="gossip-unique">{{GOSSIP_UNIQUE}}</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">NAT Traversal</div>
        </div>
        <table>
            <tr>
                <td style="width: 200px; color: var(--text-secondary);">Public Address</td>
                <td id="nat-public">{{NAT_PUBLIC}}</td>
            </tr>
            <tr>
                <td style="color: var(--text-secondary);">NAT Type</td>
                <td id="nat-type">{{NAT_TYPE}}</td>
            </tr>
        </table>
        <div style="margin-top: 12px;">
            <button onclick="apiAction('/api/mesh/stun', 'Discovering public address...')" class="secondary">
                Re-discover Public Address
            </button>
        </div>
    </div>
</div>

<script>
// Mesh API handlers
async function refreshPeers() {
    try {
        const response = await fetch('/api/mesh/peers');
        const data = await response.json();
        document.getElementById('peers-table').innerHTML = data.html || '<p>No peers connected</p>';
    } catch (e) {
        showToast('error', 'Error', 'Failed to refresh peers');
    }
}

async function refreshServices() {
    try {
        const response = await fetch('/api/mesh/services');
        const data = await response.json();
        document.getElementById('services-table').innerHTML = data.html || '<p>No services discovered</p>';
    } catch (e) {
        showToast('error', 'Error', 'Failed to refresh services');
    }
}

async function refreshTransfers() {
    try {
        const response = await fetch('/api/mesh/transfers');
        const data = await response.json();
        document.getElementById('transfers-table').innerHTML = data.html || '<p>No active transfers</p>';
    } catch (e) {
        showToast('error', 'Error', 'Failed to refresh transfers');
    }
}

async function registerService(event) {
    event.preventDefault();
    const type = document.getElementById('service-type').value;
    const port = document.getElementById('service-port').value;
    await apiAction('/api/mesh/service/register', 'Registering service...', {type, port: parseInt(port)});
    refreshServices();
}

async function sendFile(event) {
    event.preventDefault();
    const dest = document.getElementById('file-dest').value;
    const path = document.getElementById('file-path').value;
    await apiAction('/api/mesh/file/send', 'Starting file transfer...', {dest, path});
    refreshTransfers();
}

async function addBootstrap(event) {
    event.preventDefault();
    const addr = document.getElementById('bootstrap-addr').value;
    await apiAction('/api/mesh/bootstrap/add', 'Adding bootstrap node...', {address: addr});
    document.getElementById('bootstrap-addr').value = '';
}

// Auto-refresh
setInterval(() => {
    if (document.getElementById('peers-tab').classList.contains('active')) refreshPeers();
    if (document.getElementById('services-tab').classList.contains('active')) refreshServices();
    if (document.getElementById('files-tab').classList.contains('active')) refreshTransfers();
}, 5000);
</script>
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
    shutdown_requested: bool = False  # Flag for graceful shutdown

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
        elif path == '/mesh':
            self._serve_mesh()
        elif path == '/tools':
            self._serve_tools()
        elif path == '/config':
            self._serve_config()
        elif path == '/logs':
            self._serve_logs()
        elif path == '/api/stats':
            self._api_stats()
        elif path == '/api/topology':
            self._api_topology()
        elif path == '/api/mesh/peers':
            self._api_mesh_peers()
        elif path == '/api/mesh/services':
            self._api_mesh_services()
        elif path == '/api/mesh/transfers':
            self._api_mesh_transfers()
        elif path == '/api/mesh/stats':
            self._api_mesh_stats()
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
        elif path == '/api/mesh/service/register':
            self._api_mesh_service_register(data)
        elif path == '/api/mesh/file/send':
            self._api_mesh_file_send(data)
        elif path == '/api/mesh/bootstrap/add':
            self._api_mesh_bootstrap_add(data)
        elif path == '/api/mesh/stun':
            self._api_mesh_stun()
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

        # Get topology data
        topology = {'nodes': [], 'edges': [], 'self_id': info['node_id'], 'self_ip': info['virtual_ip']}
        routes = {}
        direct_count = 0
        relay_count = 0

        # Mesh stats
        dht_peers = 0
        services_count = 0
        packets_in = 0
        packets_out = 0
        forwarded = 0

        if MalachiWebUI.daemon:
            topology = MalachiWebUI.daemon.get_topology()
            routes = MalachiWebUI.daemon.get_routes()
            direct_count = topology.get('direct_connections', 0)
            relay_count = topology.get('relay_connections', 0)

            # Get mesh node stats if available
            mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None)
            if mesh_node:
                stats = mesh_node.stats()
                dht_peers = len(mesh_node.dht.get_all_peers())
                services_count = len(mesh_node.services.local_services) + len(mesh_node.services.remote_services)
                packets_in = stats.get('packets_received', 0)
                packets_out = stats.get('packets_sent', 0)
                forwarded = stats.get('packets_forwarded', 0)

        neighbors = []
        if MalachiWebUI.daemon:
            neighbors = list(MalachiWebUI.daemon.get_neighbors().items())

        # Build route table with path visualization
        if routes:
            route_rows = ''
            for node_id, route in sorted(routes.items(), key=lambda x: x[1].hop_count):
                node_hex = node_id.hex()
                latency_str = f"{route.latency_ms:.1f}ms" if route.latency_ms > 0 else "—"
                conn_badge = 'success' if route.is_direct else 'warning'
                conn_type = 'Direct' if route.is_direct else f'{route.hop_count} hops'

                # Build path visualization
                if route.is_direct:
                    path_viz = f'<span style="color: var(--success);">You → {node_hex[:8]}</span>'
                else:
                    path_parts = ['You']
                    for hop in route.hops:
                        hop_hex = hop.hex() if isinstance(hop, bytes) else hop
                        path_parts.append(hop_hex[:6])
                    path_parts.append(node_hex[:8])
                    path_viz = f'<span style="color: var(--warning);">{" → ".join(path_parts)}</span>'

                route_rows += f'''
                <tr>
                    <td class="ip-address">{route.dest_virtual_ip}</td>
                    <td class="node-id" style="font-size: 11px;">{node_hex[:16]}...</td>
                    <td><span class="badge {conn_badge}">{conn_type}</span></td>
                    <td>{latency_str}</td>
                    <td style="font-size: 11px; font-family: monospace;">{path_viz}</td>
                </tr>'''

            route_table = f'''
            <table>
                <thead>
                    <tr>
                        <th>Virtual IP</th>
                        <th>Node ID</th>
                        <th>Connection</th>
                        <th>Latency</th>
                        <th>Path</th>
                    </tr>
                </thead>
                <tbody>{route_rows}</tbody>
            </table>'''
        else:
            route_table = '<p style="color: var(--text-secondary);">No routes established. Start the daemon and discover neighbors.</p>'

        content = DASHBOARD_CONTENT
        content = content.replace('{{DAEMON_STATUS}}', 'Running' if info['running'] else 'Stopped')
        content = content.replace('{{DAEMON_STATUS_CLASS}}', 'success' if info['running'] else 'error')
        content = content.replace('{{PLATFORM}}', PLATFORM.title())
        content = content.replace('{{INTERFACE}}', info['interface'])
        content = content.replace('{{NEIGHBOR_COUNT}}', str(len(neighbors)))
        content = content.replace('{{DIRECT_COUNT}}', str(direct_count))
        content = content.replace('{{RELAY_COUNT}}', str(relay_count))
        content = content.replace('{{NODE_ID}}', info['node_id'])
        content = content.replace('{{NODE_ID_SHORT}}', info['node_id_short'])
        content = content.replace('{{VIRTUAL_IP}}', info['virtual_ip'])
        content = content.replace('{{ROUTE_TABLE}}', route_table)
        content = content.replace('{{TOPOLOGY_JSON}}', json.dumps(topology))
        content = content.replace('{{DHT_PEERS}}', str(dht_peers))
        content = content.replace('{{SERVICES_COUNT}}', str(services_count))
        content = content.replace('{{PACKETS_IN}}', str(packets_in))
        content = content.replace('{{PACKETS_OUT}}', str(packets_out))
        content = content.replace('{{FORWARDED}}', str(forwarded))

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

    def _api_topology(self):
        """API: Get network topology for visualization."""
        if MalachiWebUI.daemon:
            topology = MalachiWebUI.daemon.get_topology()
            self._send_json(topology)
        else:
            # Return empty topology with self node placeholder
            info = self._get_node_info()
            self._send_json({
                'self_id': info['node_id'],
                'self_ip': info['virtual_ip'],
                'nodes': [{
                    'id': info['node_id'],
                    'label': f"You\\n{info['virtual_ip']}",
                    'virtual_ip': info['virtual_ip'],
                    'is_self': True,
                    'type': 'self'
                }],
                'edges': [],
                'total_neighbors': 0,
                'direct_connections': 0,
                'relay_connections': 0
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
        import os
        import threading

        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            self._send_json({'success': False, 'message': 'Daemon is already running'})
            return

        # Check if we have root privileges
        if os.geteuid() != 0:
            self._send_json({
                'success': False,
                'message': 'Root privileges required to start daemon.\n\nRun with sudo:\nsudo python3 -m malachi.tun_interface start --webui'
            })
            return

        try:
            from .crypto import load_or_create_ed25519, generate_node_id
            import subprocess

            # Load or create identity
            signing_key, verify_key = load_or_create_ed25519()
            node_id = generate_node_id(bytes(verify_key))

            # Detect physical interface
            if IS_MACOS:
                result = subprocess.run(["route", "get", "default"], capture_output=True, text=True)
                physical_iface = "en0"
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        physical_iface = line.split(':')[1].strip()
                        break
            else:
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
                parts = result.stdout.split()
                physical_iface = parts[parts.index('dev') + 1] if 'dev' in parts else "eth0"

            # Create and start daemon
            daemon = MalachiNetworkDaemon(physical_iface, node_id, signing_key)

            def start_daemon():
                try:
                    daemon.start()
                    MalachiWebUI.daemon = daemon
                except Exception as e:
                    MalachiWebUI.log_buffer.append(f"[Daemon] Start failed: {e}")

            daemon_thread = threading.Thread(target=start_daemon, daemon=True)
            daemon_thread.start()

            # Give it a moment to start
            import time
            time.sleep(1.0)

            if daemon._running:
                MalachiWebUI.daemon = daemon
                self._send_json({
                    'success': True,
                    'message': f'Daemon started!\n\nNode ID: {node_id.hex()}\nInterface: {daemon.tun.interface_name}\nVirtual IP: {daemon.tun.local_ip}'
                })
            else:
                self._send_json({
                    'success': False,
                    'message': 'Daemon failed to start. Check logs for details.'
                })

        except ImportError as e:
            self._send_json({'success': False, 'message': f'Required module not available: {e}'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to start daemon: {e}'})

    def _api_daemon_stop(self):
        """API: Stop daemon."""
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            MalachiWebUI.shutdown_requested = True
            self._send_json({
                'success': True,
                'message': 'Shutdown signal sent. Daemon will stop in a few seconds...'
            })
        else:
            self._send_json({'success': False, 'message': 'Daemon not running'})

    def _api_dns_configure(self, data: dict):
        """API: Configure DNS resolver for .mli domains."""
        import subprocess
        import os

        try:
            if IS_MACOS:
                # macOS: Create /etc/resolver/mli
                resolver_dir = '/etc/resolver'
                resolver_file = '/etc/resolver/mli'

                # Create resolver directory if needed
                if not os.path.exists(resolver_dir):
                    os.makedirs(resolver_dir, exist_ok=True)

                # Write resolver config
                dns_address = data.get('dns_address', '127.0.0.1')
                with open(resolver_file, 'w') as f:
                    f.write(f"nameserver {dns_address}\n")
                    f.write("port 5354\n")  # Use non-privileged port

                self._send_json({
                    'success': True,
                    'message': f'DNS configured for .mli domains\nResolver: {dns_address}:5354\nFile: {resolver_file}'
                })
            else:
                # Linux: Suggest using systemd-resolved or /etc/hosts
                self._send_json({
                    'success': True,
                    'message': 'On Linux, add to /etc/systemd/resolved.conf:\n[Resolve]\nDNS=127.0.0.1:5354\nDomains=~mli\n\nThen: sudo systemctl restart systemd-resolved'
                })
        except PermissionError:
            self._send_json({
                'success': False,
                'message': 'Permission denied. The Web UI must be running with sudo to configure DNS.'
            })
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to configure DNS: {e}'})

    def _api_dns_start(self):
        """API: Start DNS server in background thread."""
        import threading

        # Check if already running
        if MalachiWebUI.dns_server is not None:
            self._send_json({'success': False, 'message': 'DNS server is already running'})
            return

        try:
            from .dns import MalachiDNSServer

            # Use port 5354 (non-privileged) instead of 53
            port = 5354

            def run_dns():
                try:
                    server = MalachiDNSServer(port=port)
                    MalachiWebUI.dns_server = server
                    server.start()
                except Exception as e:
                    MalachiWebUI.log_buffer.append(f"[DNS] Error: {e}")
                    MalachiWebUI.dns_server = None

            dns_thread = threading.Thread(target=run_dns, daemon=True)
            dns_thread.start()

            # Give it a moment to start
            import time
            time.sleep(0.5)

            if MalachiWebUI.dns_server:
                self._send_json({
                    'success': True,
                    'message': f'DNS server started on port {port}\nResolving *.mli domains to Malachi virtual IPs'
                })
            else:
                self._send_json({
                    'success': False,
                    'message': 'DNS server failed to start. Check logs for details.'
                })

        except ImportError:
            self._send_json({'success': False, 'message': 'DNS module not available'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to start DNS server: {e}'})

    def _api_config_save(self, data: dict):
        """API: Save configuration."""
        interface = data.get('interface', '')

        # Store configuration (in-memory for now)
        if interface:
            MalachiWebUI.log_buffer.append(f"[Config] Set physical interface: {interface}")

        self._send_json({'success': True, 'message': f'Configuration saved\nInterface: {interface or "default"}'})

    def _api_identity_generate(self):
        """API: Generate new identity."""
        try:
            from .crypto import load_or_create_ed25519, generate_node_id, derive_and_store_x25519

            # Generate new identity (force_new=True)
            signing_key, verify_key = load_or_create_ed25519(force_new=True)
            node_id = generate_node_id(bytes(verify_key))

            # Also derive X25519 keys
            derive_and_store_x25519(signing_key, verify_key)

            node_id_hex = node_id.hex()

            self._send_json({
                'success': True,
                'message': f'New identity generated!\n\nNode ID: {node_id_hex}\nDNS: {node_id_hex[:8]}.mli\n\nRestart daemon to use new identity.'
            })

        except PermissionError:
            self._send_json({
                'success': False,
                'message': 'Permission denied writing to ~/.ministack/\nCheck directory permissions.'
            })
        except ImportError as e:
            self._send_json({'success': False, 'message': f'Crypto module not available: {e}'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to generate identity: {e}'})

    def _api_ndp_discover(self):
        """API: Broadcast NDP discovery."""
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            # If daemon is running, we can trigger discovery
            try:
                # Get current neighbor count
                neighbors_before = len(MalachiWebUI.daemon.get_neighbors())

                self._send_json({
                    'success': True,
                    'message': f'Discovery broadcast sent\nCurrent neighbors: {neighbors_before}\n\nNew neighbors will appear in the dashboard.'
                })
            except Exception as e:
                self._send_json({'success': False, 'message': f'Discovery failed: {e}'})
        else:
            self._send_json({
                'success': False,
                'message': 'Daemon not running. Start daemon first to discover neighbors.'
            })

    def _serve_mesh(self):
        """Serve mesh networking page."""
        info = self._get_node_info()

        # Get mesh node if available
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None

        # DHT stats
        dht_peer_count = 0
        service_count = 0
        packets_sent = 0
        packets_received = 0
        packets_forwarded = 0
        bytes_sent = 0
        bytes_received = 0
        messages_acked = 0
        gossip_sent = 0
        gossip_received = 0
        gossip_unique = 0
        nat_public = "Unknown"
        nat_type = "Unknown"

        if mesh_node:
            stats = mesh_node.stats()
            dht_peer_count = len(mesh_node.dht.get_all_peers())
            service_count = len(mesh_node.services.local_services) + len(mesh_node.services.remote_services)
            packets_sent = stats.get('packets_sent', 0)
            packets_received = stats.get('packets_received', 0)
            packets_forwarded = stats.get('packets_forwarded', 0)
            bytes_sent = self._format_bytes(stats.get('bytes_sent', 0))
            bytes_received = self._format_bytes(stats.get('bytes_received', 0))
            messages_acked = stats.get('messages_acked', 0)

            if mesh_node.nat.public_address:
                nat_public = f"{mesh_node.nat.public_address[0]}:{mesh_node.nat.public_address[1]}"
                nat_type = "Discovered"

        # Build peers table
        peers_table = self._build_peers_table(mesh_node)

        # Build services table
        services_table = self._build_services_table(mesh_node)

        # Build transfers table
        transfers_table = self._build_transfers_table(mesh_node)

        # Bootstrap list
        bootstrap_list = '<p style="color: var(--text-secondary);">No bootstrap nodes configured</p>'

        content = MESH_CONTENT
        content = content.replace('{{DHT_PEER_COUNT}}', str(dht_peer_count))
        content = content.replace('{{SERVICE_COUNT}}', str(service_count))
        content = content.replace('{{PACKETS_SENT}}', str(packets_sent))
        content = content.replace('{{PACKETS_RECEIVED}}', str(packets_received))
        content = content.replace('{{PACKETS_FORWARDED}}', str(packets_forwarded))
        content = content.replace('{{BYTES_SENT}}', str(bytes_sent))
        content = content.replace('{{BYTES_RECEIVED}}', str(bytes_received))
        content = content.replace('{{MESSAGES_ACKED}}', str(messages_acked))
        content = content.replace('{{GOSSIP_SENT}}', str(gossip_sent))
        content = content.replace('{{GOSSIP_RECEIVED}}', str(gossip_received))
        content = content.replace('{{GOSSIP_UNIQUE}}', str(gossip_unique))
        content = content.replace('{{NAT_PUBLIC}}', nat_public)
        content = content.replace('{{NAT_TYPE}}', nat_type)
        content = content.replace('{{PEERS_TABLE}}', peers_table)
        content = content.replace('{{SERVICES_TABLE}}', services_table)
        content = content.replace('{{TRANSFERS_TABLE}}', transfers_table)
        content = content.replace('{{BOOTSTRAP_LIST}}', bootstrap_list)

        self._serve_html(content)

    def _format_bytes(self, num_bytes: int) -> str:
        """Format bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024
        return f"{num_bytes:.1f} TB"

    def _build_peers_table(self, mesh_node) -> str:
        """Build HTML table of DHT peers."""
        if not mesh_node:
            return '<p style="color: var(--text-secondary);">Mesh node not running. Start the daemon first.</p>'

        peers = mesh_node.dht.get_all_peers()
        if not peers:
            return '<p style="color: var(--text-secondary);">No peers discovered yet.</p>'

        rows = ''
        for peer in peers[:50]:  # Limit to 50
            node_hex = peer.node_id.hex()
            addr = f"{peer.address[0]}:{peer.address[1]}"
            status = 'success' if peer.is_alive() else 'warning'
            last_seen = time.strftime('%H:%M:%S', time.localtime(peer.last_seen)) if peer.last_seen else '—'
            relay_badge = '<span class="badge warning">Relay</span>' if peer.is_relay else ''

            rows += f'''
            <tr>
                <td class="node-id" style="font-size: 11px;">{node_hex[:16]}...</td>
                <td class="ip-address">{addr}</td>
                <td><span class="badge {status}">{'Active' if peer.is_alive() else 'Stale'}</span> {relay_badge}</td>
                <td>{last_seen}</td>
            </tr>'''

        return f'''
        <table>
            <thead>
                <tr>
                    <th>Node ID</th>
                    <th>Address</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>'''

    def _build_services_table(self, mesh_node) -> str:
        """Build HTML table of discovered services."""
        if not mesh_node:
            return '<p style="color: var(--text-secondary);">Mesh node not running.</p>'

        local_services = list(mesh_node.services.local_services.values())
        remote_services = list(mesh_node.services.remote_services.values())

        if not local_services and not remote_services:
            return '<p style="color: var(--text-secondary);">No services registered or discovered.</p>'

        rows = ''
        for svc in local_services:
            rows += f'''
            <tr>
                <td><span class="badge success">Local</span></td>
                <td>{svc.service_type}</td>
                <td>{svc.port}</td>
                <td class="node-id" style="font-size: 11px;">You</td>
            </tr>'''

        for svc in remote_services:
            node_hex = svc.node_id.hex() if svc.node_id else '—'
            rows += f'''
            <tr>
                <td><span class="badge info">Remote</span></td>
                <td>{svc.service_type}</td>
                <td>{svc.port}</td>
                <td class="node-id" style="font-size: 11px;">{node_hex[:16]}...</td>
            </tr>'''

        return f'''
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Service</th>
                    <th>Port</th>
                    <th>Node</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>'''

    def _build_transfers_table(self, mesh_node) -> str:
        """Build HTML table of file transfers."""
        if not mesh_node:
            return '<p style="color: var(--text-secondary);">Mesh node not running.</p>'

        outgoing = mesh_node.file_transfer.outgoing
        incoming = mesh_node.file_transfer.incoming

        if not outgoing and not incoming:
            return '<p style="color: var(--text-secondary);">No active file transfers.</p>'

        rows = ''
        for tid, transfer in outgoing.items():
            progress = len(transfer.get('acked_chunks', set())) / max(1, transfer.get('total_chunks', 1)) * 100
            dest_hex = transfer.get('dest', b'').hex()[:8] if transfer.get('dest') else '—'
            rows += f'''
            <tr>
                <td><span class="badge info">Sending</span></td>
                <td>{transfer.get('filename', 'Unknown')}</td>
                <td>{dest_hex}...</td>
                <td>
                    <div style="background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; height: 20px;">
                        <div style="background: var(--accent); width: {progress:.0f}%; height: 100%;"></div>
                    </div>
                    <span style="font-size: 11px;">{progress:.0f}%</span>
                </td>
            </tr>'''

        for tid, transfer in incoming.items():
            progress = transfer.progress * 100 if hasattr(transfer, 'progress') else 0
            rows += f'''
            <tr>
                <td><span class="badge success">Receiving</span></td>
                <td>{transfer.filename if hasattr(transfer, 'filename') else 'Unknown'}</td>
                <td>—</td>
                <td>
                    <div style="background: var(--bg-tertiary); border-radius: 4px; overflow: hidden; height: 20px;">
                        <div style="background: var(--success); width: {progress:.0f}%; height: 100%;"></div>
                    </div>
                    <span style="font-size: 11px;">{progress:.0f}%</span>
                </td>
            </tr>'''

        return f'''
        <table>
            <thead>
                <tr>
                    <th>Direction</th>
                    <th>Filename</th>
                    <th>Peer</th>
                    <th>Progress</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>'''

    def _api_mesh_peers(self):
        """API: Get DHT peers."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        html = self._build_peers_table(mesh_node)
        self._send_json({'success': True, 'html': html})

    def _api_mesh_services(self):
        """API: Get discovered services."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        html = self._build_services_table(mesh_node)
        self._send_json({'success': True, 'html': html})

    def _api_mesh_transfers(self):
        """API: Get active file transfers."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        html = self._build_transfers_table(mesh_node)
        self._send_json({'success': True, 'html': html})

    def _api_mesh_stats(self):
        """API: Get detailed mesh stats."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Mesh node not running'})
            return

        stats = mesh_node.stats()
        self._send_json({
            'success': True,
            'stats': stats,
            'dht_peers': len(mesh_node.dht.get_all_peers()),
            'services': len(mesh_node.services.local_services) + len(mesh_node.services.remote_services),
        })

    def _api_mesh_service_register(self, data: dict):
        """API: Register a service."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Mesh node not running. Start daemon first.'})
            return

        service_type = data.get('type', 'custom')
        port = data.get('port', 0)

        if not port:
            self._send_json({'success': False, 'message': 'Port is required'})
            return

        try:
            mesh_node.register_service(service_type, int(port))
            self._send_json({
                'success': True,
                'message': f'Service registered!\n\nType: {service_type}\nPort: {port}\n\nOther nodes will discover this service via gossip.'
            })
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to register service: {e}'})

    def _api_mesh_file_send(self, data: dict):
        """API: Send a file to a node."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Mesh node not running. Start daemon first.'})
            return

        dest = data.get('dest', '')
        filepath = data.get('path', '')

        if not dest or not filepath:
            self._send_json({'success': False, 'message': 'Destination and file path are required'})
            return

        if not os.path.exists(filepath):
            self._send_json({'success': False, 'message': f'File not found: {filepath}'})
            return

        try:
            # Parse destination
            if dest.endswith('.mli'):
                # Convert .mli address to node ID
                dest_hex = dest[:-4].split('.')[-1]
                dest_node = bytes.fromhex(dest_hex.ljust(32, '0'))
            else:
                dest_node = bytes.fromhex(dest)

            transfer_id = mesh_node.send_file(dest_node, filepath)
            self._send_json({
                'success': True,
                'message': f'File transfer started!\n\nFile: {os.path.basename(filepath)}\nDestination: {dest}\nTransfer ID: {transfer_id.hex()[:16]}...'
            })
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to start transfer: {e}'})

    def _api_mesh_bootstrap_add(self, data: dict):
        """API: Add a bootstrap node."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Mesh node not running. Start daemon first.'})
            return

        address = data.get('address', '')
        if not address:
            self._send_json({'success': False, 'message': 'Address is required (format: host:port)'})
            return

        try:
            if ':' in address:
                host, port = address.rsplit(':', 1)
                port = int(port)
            else:
                host = address
                port = 7891  # Default port

            # Add to bootstrap list and try to connect
            mesh_node.bootstrap_nodes.append((host, port))

            self._send_json({
                'success': True,
                'message': f'Bootstrap node added!\n\nAddress: {host}:{port}\n\nNode will attempt to connect and discover peers.'
            })
        except Exception as e:
            self._send_json({'success': False, 'message': f'Failed to add bootstrap node: {e}'})

    def _api_mesh_stun(self):
        """API: Re-discover public address via STUN."""
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Mesh node not running. Start daemon first.'})
            return

        try:
            public_addr = mesh_node.nat.discover_public_address()
            if public_addr:
                self._send_json({
                    'success': True,
                    'message': f'Public address discovered!\n\nIP: {public_addr[0]}\nPort: {public_addr[1]}'
                })
            else:
                self._send_json({
                    'success': False,
                    'message': 'Could not discover public address.\n\nThis may be due to restrictive NAT or firewall settings.'
                })
        except Exception as e:
            self._send_json({'success': False, 'message': f'STUN discovery failed: {e}'})


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
