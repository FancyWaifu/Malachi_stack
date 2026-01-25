#!/usr/bin/env python3
"""
Malachi Web UI - Modern Dashboard Design

A browser-based interface for configuring and monitoring Malachi.
Inspired by Grafana, Netdata, and Portainer dashboards.

Features:
- Sidebar navigation with collapsible menu
- Real-time charts and gauges
- Glassmorphism card design
- Modern dark theme with cyan accents
- Responsive layout

Usage:
    python3 -m malachi.webui

Then open: http://localhost:7890
"""

import os
import sys
import json
import time
import html
import threading
import socket
import secrets
import hashlib
import re
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Optional, Any, List, Set
from collections import deque
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

WEBUI_PORT = 7890
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 100

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
# Security Helpers
# =============================================================================

def sanitize_html(text: str) -> str:
    return html.escape(str(text))

def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)

def validate_node_id(node_id: str) -> bool:
    if not node_id:
        return False
    return bool(re.match(r'^[a-fA-F0-9]{1,64}$', node_id))

def validate_ip_address(ip: str) -> bool:
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def validate_port(port: Any) -> bool:
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


@dataclass
class RateLimiter:
    requests: Dict[str, deque] = field(default_factory=dict)

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = deque()
        while self.requests[ip] and self.requests[ip][0] < now - RATE_LIMIT_WINDOW:
            self.requests[ip].popleft()
        if len(self.requests[ip]) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        self.requests[ip].append(now)
        return True


rate_limiter = RateLimiter()


@dataclass
class StatsHistory:
    max_points: int = 60
    packets_in: deque = field(default_factory=lambda: deque(maxlen=60))
    packets_out: deque = field(default_factory=lambda: deque(maxlen=60))
    bytes_in: deque = field(default_factory=lambda: deque(maxlen=60))
    bytes_out: deque = field(default_factory=lambda: deque(maxlen=60))
    peer_count: deque = field(default_factory=lambda: deque(maxlen=60))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=60))

    def add_point(self, packets_in: int, packets_out: int, bytes_in: int,
                  bytes_out: int, peers: int):
        self.packets_in.append(packets_in)
        self.packets_out.append(packets_out)
        self.bytes_in.append(bytes_in)
        self.bytes_out.append(bytes_out)
        self.peer_count.append(peers)
        self.timestamps.append(time.time())

    def to_dict(self) -> dict:
        return {
            'packets_in': list(self.packets_in),
            'packets_out': list(self.packets_out),
            'bytes_in': list(self.bytes_in),
            'bytes_out': list(self.bytes_out),
            'peer_count': list(self.peer_count),
            'timestamps': list(self.timestamps),
        }


stats_history = StatsHistory()

# Initialize with some demo data points for initial chart display
for i in range(10):
    stats_history.add_point(
        random.randint(0, 5),
        random.randint(0, 3),
        random.randint(0, 1000),
        random.randint(0, 800),
        0
    )


# =============================================================================
# Modern CSS - Inspired by Grafana/Netdata/Portainer
# =============================================================================

CSS_STYLES = '''
:root {
    /* Dark theme - inspired by Grafana */
    --bg-canvas: #111217;
    --bg-primary: #181b1f;
    --bg-secondary: #22252a;
    --bg-card: #1e2127;
    --bg-hover: #2a2e35;

    /* Borders */
    --border-color: #2d3139;
    --border-light: #383d47;

    /* Text */
    --text-primary: #e4e6eb;
    --text-secondary: #9da5b4;
    --text-muted: #6b7280;

    /* Accent - Cyan/Teal theme like Netdata */
    --accent: #00d4aa;
    --accent-hover: #00f0c0;
    --accent-dim: rgba(0, 212, 170, 0.15);

    /* Status colors */
    --success: #22c55e;
    --warning: #f59e0b;
    --error: #ef4444;
    --info: #3b82f6;

    /* Gradients */
    --gradient-accent: linear-gradient(135deg, #00d4aa 0%, #00a3cc 100%);
    --gradient-card: linear-gradient(180deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0) 100%);

    /* Shadows */
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
    --shadow-md: 0 4px 12px rgba(0,0,0,0.4);
    --shadow-lg: 0 8px 24px rgba(0,0,0,0.5);
    --shadow-glow: 0 0 20px rgba(0, 212, 170, 0.3);

    /* Sidebar */
    --sidebar-width: 240px;
    --sidebar-collapsed: 64px;

    /* Transitions */
    --transition-fast: 0.15s ease;
    --transition-normal: 0.25s ease;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

html, body {
    height: 100%;
}

body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg-canvas);
    color: var(--text-primary);
    line-height: 1.5;
    overflow-x: hidden;
}

/* Layout */
.app-container {
    display: flex;
    min-height: 100vh;
}

/* Sidebar */
.sidebar {
    width: var(--sidebar-width);
    background: var(--bg-primary);
    border-right: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    position: fixed;
    top: 0;
    left: 0;
    height: 100vh;
    z-index: 100;
    transition: width var(--transition-normal);
}

.sidebar.collapsed {
    width: var(--sidebar-collapsed);
}

.sidebar-header {
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    gap: 12px;
}

.sidebar-logo {
    width: 32px;
    height: 32px;
    background: var(--gradient-accent);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 16px;
    color: #000;
    flex-shrink: 0;
}

.sidebar-title {
    font-size: 18px;
    font-weight: 600;
    color: var(--text-primary);
    white-space: nowrap;
    overflow: hidden;
}

.sidebar.collapsed .sidebar-title {
    display: none;
}

.sidebar-nav {
    flex: 1;
    padding: 12px 8px;
    overflow-y: auto;
}

.nav-section {
    margin-bottom: 24px;
}

.nav-section-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 8px 12px;
    white-space: nowrap;
}

.sidebar.collapsed .nav-section-title {
    display: none;
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    color: var(--text-secondary);
    text-decoration: none;
    border-radius: 6px;
    margin-bottom: 2px;
    transition: all var(--transition-fast);
    white-space: nowrap;
}

.nav-item:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
}

.nav-item.active {
    background: var(--accent-dim);
    color: var(--accent);
}

.nav-item.active::before {
    content: '';
    position: absolute;
    left: 0;
    width: 3px;
    height: 24px;
    background: var(--accent);
    border-radius: 0 3px 3px 0;
}

.nav-icon {
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    flex-shrink: 0;
}

.nav-label {
    flex: 1;
    font-size: 14px;
}

.sidebar.collapsed .nav-label {
    display: none;
}

.sidebar-footer {
    padding: 12px;
    border-top: 1px solid var(--border-color);
}

.sidebar-toggle {
    width: 100%;
    padding: 10px;
    background: transparent;
    border: 1px solid var(--border-color);
    border-radius: 6px;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 13px;
    transition: all var(--transition-fast);
}

.sidebar-toggle:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
}

/* Main Content */
.main-content {
    flex: 1;
    margin-left: var(--sidebar-width);
    transition: margin-left var(--transition-normal);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.sidebar.collapsed ~ .main-content {
    margin-left: var(--sidebar-collapsed);
}

/* Header */
.header {
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border-color);
    padding: 0 24px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 50;
}

.header-left {
    display: flex;
    align-items: center;
    gap: 16px;
}

.page-title {
    font-size: 20px;
    font-weight: 600;
}

.header-right {
    display: flex;
    align-items: center;
    gap: 12px;
}

.status-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 500;
}

.status-badge.online {
    background: rgba(34, 197, 94, 0.15);
    color: var(--success);
}

.status-badge.offline {
    background: rgba(239, 68, 68, 0.15);
    color: var(--error);
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: currentColor;
    animation: pulse-dot 2s infinite;
}

@keyframes pulse-dot {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.6; transform: scale(0.9); }
}

.status-badge.offline .status-dot {
    animation: none;
}

/* Page Content */
.page-content {
    flex: 1;
    padding: 24px;
    overflow-y: auto;
}

/* Cards - Glassmorphism style */
.card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    overflow: hidden;
}

.card-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--gradient-card);
}

.card-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
}

.card-title-icon {
    color: var(--accent);
}

.card-body {
    padding: 20px;
}

.card-footer {
    padding: 12px 20px;
    border-top: 1px solid var(--border-color);
    background: rgba(0,0,0,0.2);
}

/* Stat Cards */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}

.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: var(--gradient-accent);
    opacity: 0;
    transition: opacity var(--transition-fast);
}

.stat-card:hover::before {
    opacity: 1;
}

.stat-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 12px;
}

.stat-icon {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
}

.stat-icon.green { background: rgba(34, 197, 94, 0.15); color: var(--success); }
.stat-icon.blue { background: rgba(59, 130, 246, 0.15); color: var(--info); }
.stat-icon.yellow { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
.stat-icon.cyan { background: var(--accent-dim); color: var(--accent); }
.stat-icon.red { background: rgba(239, 68, 68, 0.15); color: var(--error); }

.stat-value {
    font-size: 28px;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1.2;
    margin-bottom: 4px;
}

.stat-label {
    font-size: 13px;
    color: var(--text-secondary);
}

.stat-change {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
    padding: 2px 6px;
    border-radius: 4px;
    margin-top: 8px;
}

.stat-change.up {
    background: rgba(34, 197, 94, 0.15);
    color: var(--success);
}

.stat-change.down {
    background: rgba(239, 68, 68, 0.15);
    color: var(--error);
}

/* Charts */
.chart-container {
    position: relative;
    min-height: 220px;
    height: 250px;
    background: rgba(0,0,0,0.2);
    border-radius: 8px;
    padding: 16px;
    overflow: hidden;
}

.chart-canvas {
    width: 100%;
    height: 100%;
    display: block;
}

/* Gauge */
.gauge-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 20px;
}

.gauge-svg {
    width: 160px;
    height: 100px;
}

.gauge-label {
    font-size: 13px;
    color: var(--text-secondary);
    margin-top: 8px;
}

.gauge-value {
    font-size: 24px;
    font-weight: 700;
    color: var(--text-primary);
}

/* Tables */
.table-container {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th, td {
    text-align: left;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-color);
}

th {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    background: rgba(0,0,0,0.2);
}

tr:hover td {
    background: var(--bg-hover);
}

/* Badges */
.badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 500;
}

.badge.success { background: rgba(34, 197, 94, 0.15); color: var(--success); }
.badge.warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
.badge.error { background: rgba(239, 68, 68, 0.15); color: var(--error); }
.badge.info { background: rgba(59, 130, 246, 0.15); color: var(--info); }
.badge.accent { background: var(--accent-dim); color: var(--accent); }

/* Forms */
.form-group {
    margin-bottom: 16px;
}

.form-label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    margin-bottom: 6px;
}

.form-input, .form-select {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 14px;
    transition: all var(--transition-fast);
}

.form-input:focus, .form-select:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-dim);
}

.form-input::placeholder {
    color: var(--text-muted);
}

.form-row {
    display: flex;
    gap: 12px;
    align-items: flex-end;
}

.form-row .form-group {
    flex: 1;
}

/* Buttons */
.btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px 18px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all var(--transition-fast);
}

.btn-primary {
    background: var(--gradient-accent);
    color: #000;
}

.btn-primary:hover {
    box-shadow: var(--shadow-glow);
    transform: translateY(-1px);
}

.btn-secondary {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
}

.btn-secondary:hover {
    background: var(--bg-hover);
    border-color: var(--border-light);
}

.btn-danger {
    background: rgba(239, 68, 68, 0.15);
    color: var(--error);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.btn-danger:hover {
    background: rgba(239, 68, 68, 0.25);
}

.btn-sm {
    padding: 6px 12px;
    font-size: 13px;
}

.btn-icon {
    width: 36px;
    height: 36px;
    padding: 0;
    border-radius: 8px;
}

/* Tabs */
.tabs {
    display: flex;
    gap: 4px;
    padding: 4px;
    background: var(--bg-secondary);
    border-radius: 10px;
    margin-bottom: 20px;
}

.tab {
    padding: 10px 20px;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-secondary);
    background: transparent;
    border: none;
    cursor: pointer;
    transition: all var(--transition-fast);
}

.tab:hover {
    color: var(--text-primary);
}

.tab.active {
    background: var(--bg-card);
    color: var(--accent);
    box-shadow: var(--shadow-sm);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

/* Console */
.console {
    background: #0a0c0f;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.6;
    color: #00d4aa;
    height: 300px;
    overflow-y: auto;
}

.console .error { color: #ef4444; }
.console .warning { color: #f59e0b; }
.console .info { color: #3b82f6; }
.console .success { color: #22c55e; }
.console .timestamp { color: #6b7280; }

/* Node ID / Code */
.mono {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12px;
}

.node-id {
    color: var(--accent);
}

/* Progress bar */
.progress {
    height: 6px;
    background: var(--bg-secondary);
    border-radius: 3px;
    overflow: hidden;
}

.progress-bar {
    height: 100%;
    background: var(--gradient-accent);
    border-radius: 3px;
    transition: width 0.3s ease;
}

/* Toast notifications */
.toast-container {
    position: fixed;
    top: 80px;
    right: 24px;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.toast {
    min-width: 320px;
    max-width: 420px;
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 16px;
    box-shadow: var(--shadow-lg);
    display: flex;
    gap: 12px;
    animation: slideIn 0.3s ease;
}

.toast.success { border-left: 3px solid var(--success); }
.toast.error { border-left: 3px solid var(--error); }
.toast.info { border-left: 3px solid var(--info); }
.toast.warning { border-left: 3px solid var(--warning); }

.toast-icon {
    font-size: 20px;
    flex-shrink: 0;
}

.toast.success .toast-icon { color: var(--success); }
.toast.error .toast-icon { color: var(--error); }
.toast.info .toast-icon { color: var(--info); }
.toast.warning .toast-icon { color: var(--warning); }

.toast-content { flex: 1; }
.toast-title { font-weight: 600; margin-bottom: 2px; }
.toast-message { font-size: 13px; color: var(--text-secondary); }

.toast-close {
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font-size: 18px;
    padding: 0;
    line-height: 1;
}

@keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

/* Topology */
.topology-container {
    position: relative;
    min-height: 300px;
    height: 350px;
    background: rgba(0,0,0,0.3);
    border-radius: 8px;
    overflow: hidden;
}

.topology-canvas {
    width: 100%;
    height: 100%;
    display: block;
}

.topology-legend {
    position: absolute;
    bottom: 12px;
    left: 12px;
    display: flex;
    gap: 16px;
    font-size: 12px;
    color: var(--text-secondary);
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
}

.legend-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
}

/* Grid layouts */
.grid-2 {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
}

.grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
}

@media (max-width: 1200px) {
    .grid-3 { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 768px) {
    .grid-2, .grid-3 { grid-template-columns: 1fr; }

    .sidebar {
        transform: translateX(-100%);
    }

    .sidebar.open {
        transform: translateX(0);
    }

    .main-content {
        margin-left: 0;
    }
}

/* Utility classes */
.mb-4 { margin-bottom: 16px; }
.mb-6 { margin-bottom: 24px; }
.mt-4 { margin-top: 16px; }
.text-center { text-align: center; }
.text-muted { color: var(--text-secondary); }
.text-sm { font-size: 13px; }

/* Spinner */
.spinner {
    width: 16px;
    height: 16px;
    border: 2px solid transparent;
    border-top-color: currentColor;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}
'''


# =============================================================================
# JavaScript
# =============================================================================

JAVASCRIPT = '''
const csrfToken = '{{CSRF_TOKEN}}';
let isConnected = false;
let statsData = { history: { packets_in: [], packets_out: [], timestamps: [] } };

// Toast notifications
function showToast(type, title, message, duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast ' + type;

    const icons = { success: '✓', error: '✕', info: 'ℹ', warning: '⚠' };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ'}</span>
        <div class="toast-content">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="closeToast(this.parentElement)">×</button>
    `;

    container.appendChild(toast);

    if (duration > 0) {
        setTimeout(() => closeToast(toast), duration);
    }

    return toast;
}

function closeToast(toast) {
    if (!toast || !toast.parentElement) return;
    toast.style.animation = 'slideIn 0.3s ease reverse forwards';
    setTimeout(() => toast.remove(), 300);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// API helpers
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        }
    };

    if (data && method !== 'GET') {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(endpoint, options);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return response.json();
    } catch (err) {
        console.error('API call failed:', endpoint, err);
        throw err;
    }
}

async function apiAction(endpoint, loadingMessage, data = {}) {
    console.log('API Action:', endpoint, data);
    const loadingToast = showToast('info', 'Processing', loadingMessage, 0);

    try {
        const result = await apiCall(endpoint, 'POST', data);
        closeToast(loadingToast);

        if (result.success) {
            showToast('success', 'Success', result.message);
            setTimeout(refreshStats, 500);
            setTimeout(refreshTopology, 600);
        } else {
            showToast('error', 'Error', result.message || 'Unknown error', 8000);
        }
        return result;
    } catch (err) {
        closeToast(loadingToast);
        console.error('API action error:', err);
        showToast('error', 'Network Error', err.message || 'Connection failed');
        return { success: false, message: err.message };
    }
}

// Stats refresh
async function refreshStats() {
    try {
        const data = await apiCall('/api/stats');

        // Update connection status
        const statusEl = document.getElementById('connection-status');
        if (statusEl) {
            statusEl.className = 'status-badge ' + (data.daemon_running ? 'online' : 'offline');
            statusEl.innerHTML = `<span class="status-dot"></span> ${data.daemon_running ? 'Online' : 'Offline'}`;
        }

        // Update stat values
        const updates = {
            'daemon-status': data.daemon_running ? 'Running' : 'Stopped',
            'peer-count': data.neighbors || 0,
            'packets-in': data.packets_in || 0,
            'packets-out': data.packets_out || 0,
        };

        for (const [id, value] of Object.entries(updates)) {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        }

        if (data.history) {
            statsData.history = data.history;
        }

        // Always try to draw the chart
        drawChart();

    } catch (err) {
        console.error('Stats refresh failed:', err);
    }
}

// Initialize tabs
function initTabs() {
    document.querySelectorAll('.tabs').forEach(tabGroup => {
        const tabs = tabGroup.querySelectorAll('.tab');

        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const contentId = tab.dataset.tab;

                tabs.forEach(t => t.classList.toggle('active', t === tab));

                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.toggle('active', content.id === contentId);
                });
            });
        });
    });
}

// Sidebar toggle
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
}

// Chart drawing
function drawChart() {
    const canvas = document.getElementById('traffic-chart');
    if (!canvas) return;

    const container = canvas.parentElement;
    const rect = container.getBoundingClientRect();

    // Ensure minimum dimensions
    const width = Math.max(rect.width, 300);
    const height = Math.max(rect.height, 200);

    canvas.width = width * 2;
    canvas.height = height * 2;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';

    const ctx = canvas.getContext('2d');
    ctx.setTransform(1, 0, 0, 1, 0, 0); // Reset transform
    ctx.scale(2, 2);

    const padding = { top: 20, right: 20, bottom: 30, left: 50 };

    // Clear
    ctx.fillStyle = 'rgba(0,0,0,0.3)';
    ctx.fillRect(0, 0, width, height);

    const data = statsData.history;
    if (!data.packets_in || data.packets_in.length < 2) {
        ctx.fillStyle = '#6b7280';
        ctx.font = '14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('Collecting data...', width / 2, height / 2);
        ctx.font = '12px Inter, sans-serif';
        ctx.fillText('Stats update every 5 seconds', width / 2, height / 2 + 20);
        return;
    }

    const chartWidth = width - padding.left - padding.right;
    const chartHeight = height - padding.top - padding.bottom;

    const allValues = [...data.packets_in, ...data.packets_out];
    const maxValue = Math.max(...allValues, 1);

    // Grid lines
    ctx.strokeStyle = '#2d3139';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = padding.top + (chartHeight * i / 4);
        ctx.beginPath();
        ctx.moveTo(padding.left, y);
        ctx.lineTo(width - padding.right, y);
        ctx.stroke();

        ctx.fillStyle = '#6b7280';
        ctx.font = '11px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxValue * (4 - i) / 4), padding.left - 8, y + 4);
    }

    // Draw area fill
    const drawArea = (values, color, alpha) => {
        ctx.fillStyle = color.replace('1)', alpha + ')');
        ctx.beginPath();
        ctx.moveTo(padding.left, padding.top + chartHeight);

        values.forEach((val, i) => {
            const x = padding.left + (chartWidth * i / (values.length - 1));
            const y = padding.top + chartHeight - (chartHeight * val / maxValue);
            if (i === 0) ctx.lineTo(x, y);
            else ctx.lineTo(x, y);
        });

        ctx.lineTo(padding.left + chartWidth, padding.top + chartHeight);
        ctx.closePath();
        ctx.fill();
    };

    // Draw lines
    const drawLine = (values, color) => {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();

        values.forEach((val, i) => {
            const x = padding.left + (chartWidth * i / (values.length - 1));
            const y = padding.top + chartHeight - (chartHeight * val / maxValue);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });

        ctx.stroke();
    };

    drawArea(data.packets_in, 'rgba(34, 197, 94, 1)', '0.1');
    drawArea(data.packets_out, 'rgba(59, 130, 246, 1)', '0.1');
    drawLine(data.packets_in, '#22c55e');
    drawLine(data.packets_out, '#3b82f6');

    // Legend
    ctx.fillStyle = '#22c55e';
    ctx.fillRect(width - 120, 12, 12, 12);
    ctx.fillStyle = '#e4e6eb';
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('In', width - 104, 22);

    ctx.fillStyle = '#3b82f6';
    ctx.fillRect(width - 70, 12, 12, 12);
    ctx.fillText('Out', width - 54, 22);
}

// Topology visualization
let topologyData = { nodes: [], edges: [] };

function drawTopology() {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return;

    const container = canvas.parentElement;
    const rect = container.getBoundingClientRect();

    // Ensure minimum dimensions
    const width = Math.max(rect.width, 300);
    const height = Math.max(rect.height, 300);

    canvas.width = width * 2;
    canvas.height = height * 2;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';

    const ctx = canvas.getContext('2d');
    ctx.setTransform(1, 0, 0, 1, 0, 0); // Reset transform
    ctx.scale(2, 2);

    const centerX = width / 2;
    const centerY = height / 2;

    // Clear
    ctx.fillStyle = 'rgba(0,0,0,0.3)';
    ctx.fillRect(0, 0, width, height);

    const nodes = topologyData.nodes || [];
    const edges = topologyData.edges || [];

    if (nodes.length === 0) {
        ctx.fillStyle = '#6b7280';
        ctx.font = '14px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No peers connected', centerX, centerY - 10);
        ctx.font = '12px Inter, sans-serif';
        ctx.fillText('Start daemon and discover neighbors', centerX, centerY + 10);

        // Draw placeholder self node
        ctx.beginPath();
        ctx.arc(centerX, centerY + 50, 28, 0, 2 * Math.PI);
        ctx.fillStyle = '#00d4aa';
        ctx.shadowColor = '#00d4aa';
        ctx.shadowBlur = 15;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.fillStyle = '#000';
        ctx.font = 'bold 11px Inter, sans-serif';
        ctx.textBaseline = 'middle';
        ctx.fillText('YOU', centerX, centerY + 50);
        return;
    }

    // Position nodes
    const nodePositions = {};
    const selfNode = nodes.find(n => n.is_self);
    const otherNodes = nodes.filter(n => !n.is_self);

    if (selfNode) {
        nodePositions[selfNode.id] = { x: centerX, y: centerY };
    }

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
        ctx.strokeStyle = edge.type === 'direct' ? '#22c55e' : '#f59e0b';
        ctx.lineWidth = edge.type === 'direct' ? 2 : 1;
        ctx.setLineDash(edge.type === 'direct' ? [] : [5, 5]);
        ctx.stroke();
        ctx.setLineDash([]);
    });

    // Draw nodes
    nodes.forEach(node => {
        const pos = nodePositions[node.id];
        if (!pos) return;

        const nodeRadius = node.is_self ? 28 : 22;

        // Glow effect for self
        if (node.is_self) {
            ctx.shadowColor = '#00d4aa';
            ctx.shadowBlur = 15;
        }

        ctx.beginPath();
        ctx.arc(pos.x, pos.y, nodeRadius, 0, 2 * Math.PI);
        ctx.fillStyle = node.is_self ? '#00d4aa' :
                        node.type === 'direct' ? '#22c55e' : '#f59e0b';
        ctx.fill();

        ctx.shadowBlur = 0;

        ctx.strokeStyle = '#2d3139';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Label
        ctx.fillStyle = node.is_self ? '#000' : '#fff';
        ctx.font = node.is_self ? 'bold 11px Inter, sans-serif' : '10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        if (node.is_self) {
            ctx.fillText('YOU', pos.x, pos.y);
        } else {
            ctx.fillText(node.id.substring(0, 6), pos.x, pos.y - 4);
            ctx.font = '9px Inter, sans-serif';
            ctx.fillStyle = '#e4e6eb';
            ctx.fillText(node.virtual_ip || '', pos.x, pos.y + 8);
        }
    });
}

async function refreshTopology() {
    try {
        topologyData = await apiCall('/api/topology');
        drawTopology();
    } catch (e) {}
}

// Form handlers
function initForms() {
    document.querySelectorAll('form[data-ajax]').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(form);
            const data = Object.fromEntries(formData);
            const output = document.getElementById(form.dataset.output);
            const submitBtn = form.querySelector('button[type="submit"]');
            const originalHtml = submitBtn.innerHTML;

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span>';

            try {
                const result = await apiCall(form.action, 'POST', data);

                if (output) {
                    const timestamp = new Date().toLocaleTimeString();
                    const className = result.success ? 'success' : 'error';
                    output.innerHTML += `<span class="timestamp">[${timestamp}]</span> <span class="${className}">${escapeHtml(result.message)}</span>\\n\\n`;
                    output.scrollTop = output.scrollHeight;
                }
            } catch (err) {
                if (output) {
                    output.innerHTML += `<span class="error">Error: ${escapeHtml(err.message)}</span>\\n\\n`;
                }
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalHtml;
            }
        });
    });
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('success', 'Copied', 'Text copied to clipboard', 2000);
    });
}

// Export logs
function exportLogs() {
    const console = document.getElementById('log-output');
    if (!console) return;

    const text = console.textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'malachi-logs-' + new Date().toISOString().slice(0, 10) + '.txt';
    a.click();

    URL.revokeObjectURL(url);
    showToast('success', 'Exported', 'Logs downloaded', 2000);
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initForms();

    // Restore sidebar state
    if (localStorage.getItem('sidebar-collapsed') === 'true') {
        document.querySelector('.sidebar')?.classList.add('collapsed');
    }

    // Initial data load
    refreshStats();
    refreshTopology();

    // Periodic refresh
    setInterval(refreshStats, 5000);
    setInterval(refreshTopology, 10000);

    // Resize handlers
    let resizeTimeout;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
            drawTopology();
            drawChart();
        }, 100);
    });

    // Draw visualizations after layout settles
    setTimeout(() => { drawTopology(); drawChart(); }, 100);
    setTimeout(() => { drawTopology(); drawChart(); }, 500);
    setTimeout(() => { drawTopology(); drawChart(); }, 1000);
});

// Global click handler for nav items (ensure sidebar navigation works)
document.addEventListener('click', (e) => {
    const navItem = e.target.closest('.nav-item');
    if (navItem && navItem.href) {
        // Let the browser handle the navigation
        return;
    }
});
'''


# =============================================================================
# HTML Templates
# =============================================================================

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malachi - {{PAGE_TITLE}}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>{{CSS_STYLES}}</style>
</head>
<body>
    <div id="toast-container" class="toast-container"></div>

    <div class="app-container">
        <!-- Sidebar -->
        <aside class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-logo">M</div>
                <span class="sidebar-title">Malachi</span>
            </div>

            <nav class="sidebar-nav">
                <div class="nav-section">
                    <div class="nav-section-title">Overview</div>
                    <a href="/" class="nav-item {{NAV_DASHBOARD}}">
                        <span class="nav-icon">◉</span>
                        <span class="nav-label">Dashboard</span>
                    </a>
                    <a href="/mesh" class="nav-item {{NAV_MESH}}">
                        <span class="nav-icon">⬡</span>
                        <span class="nav-label">Mesh Network</span>
                    </a>
                </div>

                <div class="nav-section">
                    <div class="nav-section-title">Tools</div>
                    <a href="/tools" class="nav-item {{NAV_TOOLS}}">
                        <span class="nav-icon">⚡</span>
                        <span class="nav-label">Network Tools</span>
                    </a>
                    <a href="/config" class="nav-item {{NAV_CONFIG}}">
                        <span class="nav-icon">⚙</span>
                        <span class="nav-label">Configuration</span>
                    </a>
                    <a href="/logs" class="nav-item {{NAV_LOGS}}">
                        <span class="nav-icon">☰</span>
                        <span class="nav-label">Logs</span>
                    </a>
                </div>
            </nav>

            <div class="sidebar-footer">
                <button class="sidebar-toggle" onclick="toggleSidebar()">
                    <span>◀</span>
                    <span class="nav-label">Collapse</span>
                </button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <header class="header">
                <div class="header-left">
                    <h1 class="page-title">{{PAGE_TITLE}}</h1>
                </div>
                <div class="header-right">
                    <div id="connection-status" class="status-badge offline">
                        <span class="status-dot"></span>
                        Offline
                    </div>
                </div>
            </header>

            <div class="page-content">
                {{CONTENT}}
            </div>
        </main>
    </div>

    <script>{{JAVASCRIPT}}</script>
</body>
</html>'''


DASHBOARD_CONTENT = '''
<!-- Stats Grid -->
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon cyan">◉</div>
        </div>
        <div class="stat-value" id="daemon-status">{{DAEMON_STATUS}}</div>
        <div class="stat-label">Daemon Status</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon blue">⬡</div>
        </div>
        <div class="stat-value" id="peer-count">{{NEIGHBOR_COUNT}}</div>
        <div class="stat-label">Connected Peers</div>
        <div class="stat-change up">{{DIRECT_COUNT}} direct</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon green">↓</div>
        </div>
        <div class="stat-value" id="packets-in">{{PACKETS_IN}}</div>
        <div class="stat-label">Packets Received</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon yellow">↑</div>
        </div>
        <div class="stat-value" id="packets-out">{{PACKETS_OUT}}</div>
        <div class="stat-label">Packets Sent</div>
    </div>
</div>

<!-- Charts Row -->
<div class="grid-2 mb-6">
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">📊</span>
                Network Traffic
            </div>
        </div>
        <div class="card-body">
            <div class="chart-container">
                <canvas id="traffic-chart" class="chart-canvas"></canvas>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">🌐</span>
                Network Topology
            </div>
            <button class="btn btn-sm btn-secondary" onclick="refreshTopology()">Refresh</button>
        </div>
        <div class="card-body">
            <div class="topology-container">
                <canvas id="topology-canvas" class="topology-canvas"></canvas>
                <div class="topology-legend">
                    <span class="legend-item"><span class="legend-dot" style="background: #00d4aa;"></span> You</span>
                    <span class="legend-item"><span class="legend-dot" style="background: #22c55e;"></span> Direct</span>
                    <span class="legend-item"><span class="legend-dot" style="background: #f59e0b;"></span> Relay</span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Node Identity & Actions -->
<div class="grid-2 mb-6">
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">🔑</span>
                Node Identity
            </div>
        </div>
        <div class="card-body">
            <table>
                <tr>
                    <td class="text-muted" style="width: 120px;">Node ID</td>
                    <td>
                        <code class="mono node-id">{{NODE_ID_SHORT}}</code>
                        <button class="btn btn-sm btn-secondary" onclick="copyToClipboard('{{NODE_ID}}')" style="margin-left: 8px;">Copy</button>
                    </td>
                </tr>
                <tr>
                    <td class="text-muted">Virtual IP</td>
                    <td><code class="mono">{{VIRTUAL_IP}}</code></td>
                </tr>
                <tr>
                    <td class="text-muted">DNS Name</td>
                    <td><code class="mono">{{DNS_NAME}}</code></td>
                </tr>
                <tr>
                    <td class="text-muted">Platform</td>
                    <td>{{PLATFORM}}</td>
                </tr>
            </table>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">⚡</span>
                Quick Actions
            </div>
        </div>
        <div class="card-body">
            <div style="display: flex; flex-direction: column; gap: 12px;">
                <button class="btn btn-primary" onclick="apiAction('/api/daemon/start', 'Starting daemon...')">
                    ▶ Start Daemon
                </button>
                <button class="btn btn-danger" onclick="apiAction('/api/daemon/stop', 'Stopping daemon...')">
                    ◼ Stop Daemon
                </button>
                <button class="btn btn-secondary" onclick="apiAction('/api/ndp/discover', 'Broadcasting discovery...')">
                    📡 Broadcast Discovery
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Route Table -->
<div class="card">
    <div class="card-header">
        <div class="card-title">
            <span class="card-title-icon">🛤️</span>
            Route Table
        </div>
        <button class="btn btn-sm btn-secondary" onclick="location.reload()">Refresh</button>
    </div>
    <div class="card-body">
        <div class="table-container">
            {{ROUTE_TABLE}}
        </div>
    </div>
</div>

<script>
topologyData = {{TOPOLOGY_JSON}};
setTimeout(() => { drawChart(); drawTopology(); }, 200);
</script>
'''


MESH_CONTENT = '''
<div class="stats-grid mb-6">
    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon cyan">⬡</div>
        </div>
        <div class="stat-value">{{DHT_PEER_COUNT}}</div>
        <div class="stat-label">DHT Peers</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon blue">◎</div>
        </div>
        <div class="stat-value">{{SERVICE_COUNT}}</div>
        <div class="stat-label">Services</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon green">↓</div>
        </div>
        <div class="stat-value">{{PACKETS_RECEIVED}}</div>
        <div class="stat-label">Packets In</div>
    </div>

    <div class="stat-card">
        <div class="stat-header">
            <div class="stat-icon yellow">↑</div>
        </div>
        <div class="stat-value">{{PACKETS_SENT}}</div>
        <div class="stat-label">Packets Out</div>
    </div>
</div>

<div class="card mb-6">
    <div class="card-header">
        <div class="tabs" style="margin: 0; padding: 0; background: transparent;">
            <button class="tab active" data-tab="peers-tab">DHT Peers</button>
            <button class="tab" data-tab="services-tab">Services</button>
            <button class="tab" data-tab="transfers-tab">Transfers</button>
            <button class="tab" data-tab="stats-tab">Statistics</button>
        </div>
    </div>

    <div id="peers-tab" class="tab-content active">
        <div class="card-body">
            <div class="table-container" id="peers-table">
                {{PEERS_TABLE}}
            </div>
        </div>
    </div>

    <div id="services-tab" class="tab-content">
        <div class="card-body">
            <div class="mb-4">
                <h4 style="margin-bottom: 12px;">Register New Service</h4>
                <form id="service-form" onsubmit="registerService(event)" class="form-row">
                    <div class="form-group">
                        <label class="form-label">Type</label>
                        <select id="service-type" class="form-select">
                            <option value="http">HTTP</option>
                            <option value="ssh">SSH</option>
                            <option value="ftp">FTP</option>
                            <option value="custom">Custom</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Port</label>
                        <input type="number" id="service-port" class="form-input" placeholder="8080" required>
                    </div>
                    <div class="form-group" style="flex: 0;">
                        <button type="submit" class="btn btn-primary">Register</button>
                    </div>
                </form>
            </div>
            <div class="table-container" id="services-table">
                {{SERVICES_TABLE}}
            </div>
        </div>
    </div>

    <div id="transfers-tab" class="tab-content">
        <div class="card-body">
            <div class="table-container" id="transfers-table">
                {{TRANSFERS_TABLE}}
            </div>
        </div>
    </div>

    <div id="stats-tab" class="tab-content">
        <div class="card-body">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{{BYTES_SENT}}</div>
                    <div class="stat-label">Bytes Sent</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{BYTES_RECEIVED}}</div>
                    <div class="stat-label">Bytes Received</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{PACKETS_FORWARDED}}</div>
                    <div class="stat-label">Forwarded</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{MESSAGES_ACKED}}</div>
                    <div class="stat-label">Acknowledged</div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
async function registerService(event) {
    event.preventDefault();
    const type = document.getElementById('service-type').value;
    const port = document.getElementById('service-port').value;
    await apiAction('/api/mesh/service/register', 'Registering...', {type, port: parseInt(port)});
}
</script>
'''


TOOLS_CONTENT = '''
<div class="card">
    <div class="card-header">
        <div class="tabs" style="margin: 0; padding: 0; background: transparent;">
            <button class="tab active" data-tab="ping-tab">Ping</button>
            <button class="tab" data-tab="lookup-tab">Lookup</button>
            <button class="tab" data-tab="scan-tab">Scan</button>
        </div>
    </div>

    <div id="ping-tab" class="tab-content active">
        <div class="card-body">
            <form action="/api/ping" method="post" data-ajax data-output="ping-output">
                <div class="form-row mb-4">
                    <div class="form-group">
                        <label class="form-label">Target (Node ID or Virtual IP)</label>
                        <input type="text" name="target" class="form-input" placeholder="a1b2c3d4 or 10.144.x.x" required>
                    </div>
                    <div class="form-group" style="flex: 0 0 100px;">
                        <label class="form-label">Count</label>
                        <input type="number" name="count" class="form-input" value="4" min="1" max="100">
                    </div>
                    <div class="form-group" style="flex: 0;">
                        <button type="submit" class="btn btn-primary">Ping</button>
                    </div>
                </div>
            </form>
            <div id="ping-output" class="console"></div>
        </div>
    </div>

    <div id="lookup-tab" class="tab-content">
        <div class="card-body">
            <form action="/api/lookup" method="post" data-ajax data-output="lookup-output">
                <div class="form-row mb-4">
                    <div class="form-group">
                        <label class="form-label">Address</label>
                        <input type="text" name="address" class="form-input" placeholder="Node ID, Virtual IP, or .mli name" required>
                    </div>
                    <div class="form-group" style="flex: 0;">
                        <button type="submit" class="btn btn-primary">Lookup</button>
                    </div>
                </div>
            </form>
            <div id="lookup-output" class="console"></div>
        </div>
    </div>

    <div id="scan-tab" class="tab-content">
        <div class="card-body">
            <form action="/api/scan" method="post" data-ajax data-output="scan-output">
                <div class="form-row mb-4">
                    <div class="form-group" style="flex: 0 0 150px;">
                        <label class="form-label">Timeout (sec)</label>
                        <input type="number" name="timeout" class="form-input" value="10" min="1" max="60">
                    </div>
                    <div class="form-group" style="flex: 0;">
                        <button type="submit" class="btn btn-primary">Start Scan</button>
                    </div>
                </div>
            </form>
            <div id="scan-output" class="console"></div>
        </div>
    </div>
</div>
'''


CONFIG_CONTENT = '''
<div class="grid-2 mb-6">
    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">🌐</span>
                Network Settings
            </div>
        </div>
        <div class="card-body">
            <div class="form-group">
                <label class="form-label">Physical Interface</label>
                <select id="config-interface" class="form-select">
                    {{INTERFACE_OPTIONS}}
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">Virtual Subnet</label>
                <input type="text" class="form-input" value="10.144.0.0/16" disabled>
                <div class="text-sm text-muted mt-4">Fixed subnet for network consistency</div>
            </div>
            <button class="btn btn-primary" onclick="apiAction('/api/config/save', 'Saving...', {interface: document.getElementById('config-interface').value})">
                Save Changes
            </button>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <div class="card-title">
                <span class="card-title-icon">🔗</span>
                DNS Configuration
            </div>
        </div>
        <div class="card-body">
            <div class="form-group">
                <label class="form-label">DNS Server</label>
                <input type="text" id="dns-address" class="form-input" value="127.0.0.1">
            </div>
            <div class="form-group">
                <label class="form-label">Status</label>
                <span class="badge {{DNS_STATUS_CLASS}}">{{DNS_STATUS}}</span>
            </div>
            <div style="display: flex; gap: 12px;">
                <button class="btn btn-primary" onclick="apiAction('/api/dns/configure', 'Configuring...', {dns_address: document.getElementById('dns-address').value})">
                    Configure
                </button>
                <button class="btn btn-secondary" onclick="apiAction('/api/dns/start', 'Starting...')">
                    Start Server
                </button>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <div class="card-title">
            <span class="card-title-icon">🔑</span>
            Identity Management
        </div>
    </div>
    <div class="card-body">
        <table class="mb-4">
            <tr>
                <td class="text-muted" style="width: 150px;">Node ID</td>
                <td><code class="mono node-id">{{NODE_ID}}</code></td>
            </tr>
            <tr>
                <td class="text-muted">Key Location</td>
                <td><code class="mono">~/.ministack/</code></td>
            </tr>
        </table>
        <button class="btn btn-danger" onclick="if(confirm('Generate new identity? This will replace your keys.')) apiAction('/api/identity/generate', 'Generating...')">
            Generate New Identity
        </button>
    </div>
</div>
'''


LOGS_CONTENT = '''
<div class="card">
    <div class="card-header">
        <div class="card-title">
            <span class="card-title-icon">☰</span>
            System Logs
        </div>
        <div style="display: flex; gap: 8px;">
            <button class="btn btn-sm btn-secondary" onclick="exportLogs()">Export</button>
            <button class="btn btn-sm btn-secondary" onclick="document.getElementById('log-output').textContent = ''">Clear</button>
        </div>
    </div>
    <div class="card-body">
        <div id="log-output" class="console" style="height: 500px;">{{LOGS}}</div>
    </div>
</div>
'''


# =============================================================================
# Web Server
# =============================================================================

class MalachiWebUI(BaseHTTPRequestHandler):
    """HTTP request handler for Malachi Web UI."""

    daemon: Optional['MalachiNetworkDaemon'] = None
    dns_server = None
    log_buffer: List[str] = []
    shutdown_requested: bool = False
    server_csrf_token: str = generate_csrf_token()

    def log_message(self, format, *args):
        message = format % args
        MalachiWebUI.log_buffer.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        if len(MalachiWebUI.log_buffer) > 1000:
            MalachiWebUI.log_buffer = MalachiWebUI.log_buffer[-500:]

    def _check_rate_limit(self) -> bool:
        return rate_limiter.is_allowed(self.client_address[0])

    def _validate_csrf(self, data: dict) -> bool:
        token = self.headers.get('X-CSRF-Token', '')
        return token == MalachiWebUI.server_csrf_token

    def do_GET(self):
        if not self._check_rate_limit():
            self._send_error(429, "Too many requests")
            return

        path = urlparse(self.path).path
        routes = {
            '/': self._serve_dashboard,
            '/dashboard': self._serve_dashboard,
            '/mesh': self._serve_mesh,
            '/tools': self._serve_tools,
            '/config': self._serve_config,
            '/logs': self._serve_logs,
            '/api/stats': self._api_stats,
            '/api/topology': self._api_topology,
            '/api/mesh/peers': self._api_mesh_peers,
            '/api/mesh/services': self._api_mesh_services,
            '/api/mesh/transfers': self._api_mesh_transfers,
            '/api/history': self._api_history,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_404()

    def do_POST(self):
        if not self._check_rate_limit():
            self._send_error(429, "Too many requests")
            return

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ''

        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json({'success': False, 'message': 'Invalid JSON'})
            return

        if not self._validate_csrf(data):
            self._send_json({'success': False, 'message': 'Invalid CSRF token'})
            return

        path = urlparse(self.path).path
        routes = {
            '/api/ping': lambda: self._api_ping(data),
            '/api/lookup': lambda: self._api_lookup(data),
            '/api/scan': lambda: self._api_scan(data),
            '/api/daemon/start': self._api_daemon_start,
            '/api/daemon/stop': self._api_daemon_stop,
            '/api/dns/configure': lambda: self._api_dns_configure(data),
            '/api/dns/start': self._api_dns_start,
            '/api/config/save': lambda: self._api_config_save(data),
            '/api/identity/generate': self._api_identity_generate,
            '/api/ndp/discover': self._api_ndp_discover,
            '/api/mesh/service/register': lambda: self._api_mesh_service_register(data),
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_json({'success': False, 'message': 'Unknown endpoint'})

    def _serve_html(self, content: str, page_title: str, nav_active: str):
        nav_states = {
            'NAV_DASHBOARD': 'active' if nav_active == 'dashboard' else '',
            'NAV_MESH': 'active' if nav_active == 'mesh' else '',
            'NAV_TOOLS': 'active' if nav_active == 'tools' else '',
            'NAV_CONFIG': 'active' if nav_active == 'config' else '',
            'NAV_LOGS': 'active' if nav_active == 'logs' else '',
        }

        page = HTML_TEMPLATE.replace('{{CONTENT}}', content)
        page = page.replace('{{PAGE_TITLE}}', page_title)
        page = page.replace('{{CSS_STYLES}}', CSS_STYLES)
        page = page.replace('{{JAVASCRIPT}}', JAVASCRIPT.replace('{{CSRF_TOKEN}}', MalachiWebUI.server_csrf_token))

        for key, value in nav_states.items():
            page = page.replace('{{' + key + '}}', value)

        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(page.encode())

    def _send_json(self, data: dict):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_404(self):
        self.send_response(404)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>404 Not Found</h1>')

    def _send_error(self, code: int, message: str):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(f'<h1>{code} {message}</h1>'.encode())

    def _get_node_info(self) -> dict:
        if MalachiWebUI.daemon and MalachiWebUI.daemon.node_id:
            node_id_bytes = MalachiWebUI.daemon.node_id
            node_id_hex = node_id_bytes.hex()

            if MALACHI_AVAILABLE:
                virtual_ip = node_id_to_virtual_ip(node_id_hex)
            else:
                node_hash = int.from_bytes(node_id_bytes[:4], 'big')
                third = (node_hash >> 8) & 0xFF
                fourth = max(2, node_hash & 0xFF)
                virtual_ip = f"10.144.{third}.{fourth}"

            return {
                'node_id': node_id_hex,
                'node_id_short': node_id_hex[:16] + '...',
                'virtual_ip': virtual_ip,
                'interface': MalachiWebUI.daemon.tun.interface_name if MalachiWebUI.daemon.tun else 'N/A',
                'running': MalachiWebUI.daemon._running,
            }
        else:
            node_id = secrets.token_hex(16)
            return {
                'node_id': node_id,
                'node_id_short': node_id[:16] + '...',
                'virtual_ip': '10.144.0.1',
                'interface': 'Not started',
                'running': False,
            }

    def _format_bytes(self, num_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if num_bytes < 1024:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024
        return f"{num_bytes:.1f} TB"

    def _get_interfaces(self) -> list:
        interfaces = []
        try:
            import subprocess
            if IS_MACOS:
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True, timeout=5)
                interfaces = [i for i in result.stdout.strip().split()
                            if not i.startswith(('lo', 'utun', 'bridge', 'awdl', 'llw'))]
            else:
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if ': ' in line and '@' not in line:
                        name = line.split(': ')[1].split(':')[0]
                        if not name.startswith(('lo', 'tun', 'tap')):
                            interfaces.append(name)
        except Exception:
            interfaces = ['eth0', 'en0']
        return interfaces

    def _build_peers_table(self, mesh_node) -> str:
        if not mesh_node:
            return '<p class="text-muted">Start the daemon to see peers.</p>'

        peers = mesh_node.dht.get_all_peers()
        if not peers:
            return '<p class="text-muted">No peers discovered yet.</p>'

        rows = ''
        for peer in peers[:50]:
            node_hex = sanitize_html(peer.node_id.hex())
            addr = f"{peer.address[0]}:{peer.address[1]}"
            status = 'success' if peer.is_alive() else 'warning'
            last_seen = time.strftime('%H:%M:%S', time.localtime(peer.last_seen)) if peer.last_seen else '-'

            rows += f'''<tr>
                <td><code class="mono node-id">{node_hex[:16]}...</code></td>
                <td><code class="mono">{sanitize_html(addr)}</code></td>
                <td><span class="badge {status}">{'Active' if peer.is_alive() else 'Stale'}</span></td>
                <td>{last_seen}</td>
            </tr>'''

        return f'<table><thead><tr><th>Node ID</th><th>Address</th><th>Status</th><th>Last Seen</th></tr></thead><tbody>{rows}</tbody></table>'

    def _build_services_table(self, mesh_node) -> str:
        if not mesh_node:
            return '<p class="text-muted">Start the daemon to see services.</p>'

        local = list(mesh_node.services.local_services.values())
        remote = list(mesh_node.services.remote_services.values())

        if not local and not remote:
            return '<p class="text-muted">No services registered.</p>'

        rows = ''
        for svc in local:
            rows += f'<tr><td><span class="badge success">Local</span></td><td>{sanitize_html(svc.service_type)}</td><td>{svc.port}</td><td>You</td></tr>'
        for svc in remote:
            node_hex = sanitize_html(svc.node_id.hex())[:16] if svc.node_id else '-'
            rows += f'<tr><td><span class="badge info">Remote</span></td><td>{sanitize_html(svc.service_type)}</td><td>{svc.port}</td><td>{node_hex}...</td></tr>'

        return f'<table><thead><tr><th>Type</th><th>Service</th><th>Port</th><th>Node</th></tr></thead><tbody>{rows}</tbody></table>'

    def _build_transfers_table(self, mesh_node) -> str:
        if not mesh_node:
            return '<p class="text-muted">Start the daemon to see transfers.</p>'
        return '<p class="text-muted">No active transfers.</p>'

    def _serve_dashboard(self):
        info = self._get_node_info()

        topology = {'nodes': [], 'edges': []}
        routes = {}
        direct_count = relay_count = dht_peers = services_count = packets_in = packets_out = forwarded = 0

        if MalachiWebUI.daemon:
            topology = MalachiWebUI.daemon.get_topology()
            routes = MalachiWebUI.daemon.get_routes()
            direct_count = topology.get('direct_connections', 0)
            relay_count = topology.get('relay_connections', 0)

            mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None)
            if mesh_node:
                stats = mesh_node.stats()
                dht_peers = len(mesh_node.dht.get_all_peers())
                services_count = len(mesh_node.services.local_services) + len(mesh_node.services.remote_services)
                packets_in = stats.get('packets_received', 0)
                packets_out = stats.get('packets_sent', 0)
                forwarded = stats.get('packets_forwarded', 0)
                stats_history.add_point(packets_in, packets_out, 0, 0, dht_peers)

        neighbors = list(MalachiWebUI.daemon.get_neighbors().items()) if MalachiWebUI.daemon else []

        # Build route table
        if routes:
            route_rows = ''
            for node_id, route in sorted(routes.items(), key=lambda x: x[1].hop_count):
                node_hex = sanitize_html(node_id.hex())
                latency_str = f"{route.latency_ms:.1f}ms" if route.latency_ms > 0 else "-"
                conn_badge = 'success' if route.is_direct else 'warning'
                conn_type = 'Direct' if route.is_direct else f'{route.hop_count} hops'

                route_rows += f'''<tr>
                    <td><code class="mono">{sanitize_html(route.dest_virtual_ip)}</code></td>
                    <td><code class="mono node-id">{node_hex[:16]}...</code></td>
                    <td><span class="badge {conn_badge}">{conn_type}</span></td>
                    <td>{latency_str}</td>
                </tr>'''

            route_table = f'<table><thead><tr><th>Virtual IP</th><th>Node ID</th><th>Type</th><th>Latency</th></tr></thead><tbody>{route_rows}</tbody></table>'
        else:
            route_table = '<p class="text-muted">No routes established. Start daemon and discover neighbors.</p>'

        content = DASHBOARD_CONTENT
        # DNS name is first 8 chars of node ID (short, memorable)
        dns_name = info['node_id'][:8] + '.mli'
        replacements = {
            'DAEMON_STATUS': 'Running' if info['running'] else 'Stopped',
            'PLATFORM': sanitize_html(PLATFORM.title()),
            'NEIGHBOR_COUNT': str(len(neighbors)),
            'DIRECT_COUNT': str(direct_count),
            'NODE_ID': sanitize_html(info['node_id']),
            'NODE_ID_SHORT': sanitize_html(info['node_id_short']),
            'VIRTUAL_IP': sanitize_html(info['virtual_ip']),
            'DNS_NAME': sanitize_html(dns_name),
            'ROUTE_TABLE': route_table,
            'TOPOLOGY_JSON': json.dumps(topology),
            'PACKETS_IN': str(packets_in),
            'PACKETS_OUT': str(packets_out),
        }

        for key, value in replacements.items():
            content = content.replace('{{' + key + '}}', value)

        self._serve_html(content, 'Dashboard', 'dashboard')

    def _serve_mesh(self):
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None

        dht_peer_count = service_count = packets_sent = packets_received = 0
        packets_forwarded = messages_acked = 0
        bytes_sent = bytes_received = "0 B"

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

        content = MESH_CONTENT
        replacements = {
            'DHT_PEER_COUNT': str(dht_peer_count),
            'SERVICE_COUNT': str(service_count),
            'PACKETS_SENT': str(packets_sent),
            'PACKETS_RECEIVED': str(packets_received),
            'PACKETS_FORWARDED': str(packets_forwarded),
            'BYTES_SENT': bytes_sent,
            'BYTES_RECEIVED': bytes_received,
            'MESSAGES_ACKED': str(messages_acked),
            'PEERS_TABLE': self._build_peers_table(mesh_node),
            'SERVICES_TABLE': self._build_services_table(mesh_node),
            'TRANSFERS_TABLE': self._build_transfers_table(mesh_node),
        }

        for key, value in replacements.items():
            content = content.replace('{{' + key + '}}', value)

        self._serve_html(content, 'Mesh Network', 'mesh')

    def _serve_tools(self):
        self._serve_html(TOOLS_CONTENT, 'Network Tools', 'tools')

    def _serve_config(self):
        info = self._get_node_info()
        interfaces = self._get_interfaces()
        options = ''.join(f'<option value="{sanitize_html(i)}">{sanitize_html(i)}</option>' for i in interfaces)
        dns_configured = os.path.exists('/etc/resolver/mli') if IS_MACOS else False

        content = CONFIG_CONTENT
        replacements = {
            'INTERFACE_OPTIONS': options,
            'NODE_ID': sanitize_html(info['node_id']),
            'DNS_STATUS': 'Configured' if dns_configured else 'Not Configured',
            'DNS_STATUS_CLASS': 'success' if dns_configured else 'warning',
        }

        for key, value in replacements.items():
            content = content.replace('{{' + key + '}}', value)

        self._serve_html(content, 'Configuration', 'config')

    def _serve_logs(self):
        logs = '\n'.join(sanitize_html(log) for log in MalachiWebUI.log_buffer[-100:])
        content = LOGS_CONTENT.replace('{{LOGS}}', logs)
        self._serve_html(content, 'System Logs', 'logs')

    # API Endpoints
    def _api_stats(self):
        info = self._get_node_info()
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None

        # Count peers from both daemon neighbors and mesh DHT
        neighbor_count = 0
        dht_peer_count = 0
        if MalachiWebUI.daemon:
            neighbor_count = len(MalachiWebUI.daemon.get_neighbors())
        if mesh_node:
            dht_peer_count = len(mesh_node.dht.get_all_peers())

        # Use the larger of the two counts (they may overlap)
        total_peers = max(neighbor_count, dht_peer_count)

        data = {
            'daemon_running': info['running'],
            'node_id': info['node_id'],
            'virtual_ip': info['virtual_ip'],
            'neighbors': total_peers,
            'dht_peers': dht_peer_count,
            'packets_in': 0,
            'packets_out': 0,
            'history': stats_history.to_dict(),
        }

        if mesh_node:
            stats = mesh_node.stats()
            data['packets_in'] = stats.get('packets_received', 0)
            data['packets_out'] = stats.get('packets_sent', 0)

        self._send_json(data)

    def _api_topology(self):
        if MalachiWebUI.daemon:
            self._send_json(MalachiWebUI.daemon.get_topology())
        else:
            info = self._get_node_info()
            self._send_json({
                'nodes': [{'id': info['node_id'], 'virtual_ip': info['virtual_ip'], 'is_self': True}],
                'edges': []
            })

    def _api_history(self):
        self._send_json(stats_history.to_dict())

    def _api_ping(self, data: dict):
        target = data.get('target', '').strip()
        count = max(1, min(100, int(data.get('count', 4))))

        if not target:
            self._send_json({'success': False, 'message': 'Target required'})
            return

        if MALACHI_AVAILABLE:
            try:
                ping = MalachiPing()
                stats = ping.ping(target, count=count, quiet=True)
                message = f"PING {target}\nTransmitted: {stats.transmitted}, Received: {stats.received}\nLoss: {stats.loss_percent:.1f}%"
                if stats.received > 0:
                    message += f"\nRTT min/avg/max: {stats.min_rtt:.2f}/{stats.avg_rtt:.2f}/{stats.max_rtt:.2f} ms"
                self._send_json({'success': True, 'message': message})
            except Exception as e:
                self._send_json({'success': False, 'message': f'Ping failed: {e}'})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_lookup(self, data: dict):
        address = data.get('address', '').strip()
        if not address:
            self._send_json({'success': False, 'message': 'Address required'})
            return

        if MALACHI_AVAILABLE:
            try:
                lookup = MalachiLookup()
                result = lookup.lookup(address)
                message = f"Address: {result['input']}\nVirtual IP: {result['virtual_ip']}\nNode ID: {result['node_id']}"
                self._send_json({'success': True, 'message': message})
            except Exception as e:
                self._send_json({'success': False, 'message': f'Lookup failed: {e}'})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_scan(self, data: dict):
        timeout = max(1, min(30, float(data.get('timeout', 10))))

        if MALACHI_AVAILABLE:
            try:
                scanner = MalachiScanner()
                nodes = scanner.scan(timeout=timeout, quiet=True)
                message = f"Found {len(nodes)} nodes:\n\n"
                for node in nodes[:20]:
                    message += f"  {node.virtual_ip}  {node.node_id.hex()[:16]}...  {node.rtt_ms:.1f}ms\n"
                self._send_json({'success': True, 'message': message})
            except Exception as e:
                self._send_json({'success': False, 'message': f'Scan failed: {e}'})
        else:
            self._send_json({'success': False, 'message': 'Malachi not available'})

    def _api_daemon_start(self):
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            self._send_json({'success': False, 'message': 'Daemon already running'})
            return

        if os.geteuid() != 0:
            self._send_json({'success': False, 'message': 'Root privileges required.\n\nRun: sudo python3 -m malachi.webui'})
            return

        try:
            from .crypto import load_or_create_ed25519, generate_node_id
            import subprocess

            signing_key, verify_key = load_or_create_ed25519()
            node_id = generate_node_id(bytes(verify_key))

            if IS_MACOS:
                result = subprocess.run(["route", "get", "default"], capture_output=True, text=True, timeout=5)
                physical_iface = "en0"
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        physical_iface = line.split(':')[1].strip()
            else:
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
                parts = result.stdout.split()
                physical_iface = parts[parts.index('dev') + 1] if 'dev' in parts else "eth0"

            daemon = MalachiNetworkDaemon(physical_iface, node_id, signing_key)

            def start_daemon():
                try:
                    daemon.start()
                    MalachiWebUI.daemon = daemon
                except Exception as e:
                    MalachiWebUI.log_buffer.append(f"[Daemon] Start failed: {e}")

            threading.Thread(target=start_daemon, daemon=True).start()
            time.sleep(1.0)

            if daemon._running:
                MalachiWebUI.daemon = daemon
                self._send_json({'success': True, 'message': f'Daemon started!\n\nNode ID: {node_id.hex()[:16]}...\nInterface: {daemon.tun.interface_name}'})
            else:
                self._send_json({'success': False, 'message': 'Daemon failed to start.'})

        except Exception as e:
            self._send_json({'success': False, 'message': f'Error: {e}'})

    def _api_daemon_stop(self):
        if MalachiWebUI.daemon and MalachiWebUI.daemon._running:
            MalachiWebUI.shutdown_requested = True
            self._send_json({'success': True, 'message': 'Shutdown signal sent.'})
        else:
            self._send_json({'success': False, 'message': 'Daemon not running'})

    def _api_dns_configure(self, data: dict):
        try:
            if IS_MACOS:
                dns_address = data.get('dns_address', '127.0.0.1')
                os.makedirs('/etc/resolver', exist_ok=True)
                with open('/etc/resolver/mli', 'w') as f:
                    f.write(f"nameserver {dns_address}\nport 5354\n")
                self._send_json({'success': True, 'message': 'DNS configured for .mli domains'})
            else:
                self._send_json({'success': True, 'message': 'Add to /etc/systemd/resolved.conf:\n[Resolve]\nDNS=127.0.0.1:5354\nDomains=~mli'})
        except PermissionError:
            self._send_json({'success': False, 'message': 'Permission denied. Run with sudo.'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Error: {e}'})

    def _api_dns_start(self):
        if MalachiWebUI.dns_server:
            self._send_json({'success': False, 'message': 'DNS server already running'})
            return

        try:
            from .dns import MalachiDNSServer

            def run_dns():
                try:
                    server = MalachiDNSServer(port=5354)
                    MalachiWebUI.dns_server = server
                    server.start()
                except Exception as e:
                    MalachiWebUI.log_buffer.append(f"[DNS] Error: {e}")
                    MalachiWebUI.dns_server = None

            threading.Thread(target=run_dns, daemon=True).start()
            time.sleep(0.5)

            if MalachiWebUI.dns_server:
                self._send_json({'success': True, 'message': 'DNS server started on port 5354'})
            else:
                self._send_json({'success': False, 'message': 'DNS server failed to start.'})
        except ImportError:
            self._send_json({'success': False, 'message': 'DNS module not available'})

    def _api_config_save(self, data: dict):
        interface = data.get('interface', '')
        if interface:
            MalachiWebUI.log_buffer.append(f"[Config] Interface: {interface}")
        self._send_json({'success': True, 'message': f'Configuration saved.\nInterface: {interface or "default"}'})

    def _api_identity_generate(self):
        try:
            from .crypto import load_or_create_ed25519, generate_node_id, derive_and_store_x25519

            signing_key, verify_key = load_or_create_ed25519(force_new=True)
            node_id = generate_node_id(bytes(verify_key))
            derive_and_store_x25519(signing_key, verify_key)

            self._send_json({'success': True, 'message': f'New identity generated!\n\nNode ID: {node_id.hex()[:16]}...\nRestart daemon to apply.'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Error: {e}'})

    def _api_ndp_discover(self):
        if not (MalachiWebUI.daemon and MalachiWebUI.daemon._running):
            self._send_json({'success': False, 'message': 'Daemon not running.'})
            return

        try:
            import struct
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.3)
            sock.bind(('', 0))

            ping = struct.pack('>B16s', 0x01, MalachiWebUI.daemon.node_id)
            sock.sendto(ping, ('255.255.255.255', 7891))

            discovered = []
            end_time = time.time() + 2.0
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(1024)
                    if len(data) >= 17 and data[0] == 0x02:
                        peer_id = data[1:17]
                        if peer_id != MalachiWebUI.daemon.node_id:
                            discovered.append({
                                'id': peer_id,
                                'id_hex': peer_id.hex()[:16],
                                'addr': addr[0],
                                'port': 7891
                            })
                except socket.timeout:
                    continue

            sock.close()

            # Add discovered peers to the mesh node's DHT
            added_count = 0
            mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None)
            if mesh_node and discovered:
                try:
                    from .mesh import PeerInfo
                    for d in discovered:
                        peer = PeerInfo(
                            node_id=d['id'],
                            address=(d['addr'], d['port'])
                        )
                        if mesh_node.dht.add_peer(peer):
                            added_count += 1
                            MalachiWebUI.log_buffer.append(
                                f"[NDP] Added peer: {d['id_hex']}... @ {d['addr']}:{d['port']}"
                            )
                except Exception as e:
                    MalachiWebUI.log_buffer.append(f"[NDP] Error adding peers: {e}")

            if discovered:
                msg = f'Found {len(discovered)} node(s), added {added_count} to DHT:\n'
                for d in discovered[:10]:
                    msg += f'  {d["addr"]}:{d["port"]} - {d["id_hex"]}...\n'
                self._send_json({'success': True, 'message': msg})
            else:
                self._send_json({'success': True, 'message': 'Broadcast sent. No new nodes found.'})

        except Exception as e:
            self._send_json({'success': False, 'message': f'Discovery failed: {e}'})

    def _api_mesh_peers(self):
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        self._send_json({'success': True, 'html': self._build_peers_table(mesh_node)})

    def _api_mesh_services(self):
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        self._send_json({'success': True, 'html': self._build_services_table(mesh_node)})

    def _api_mesh_transfers(self):
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        self._send_json({'success': True, 'html': self._build_transfers_table(mesh_node)})

    def _api_mesh_service_register(self, data: dict):
        mesh_node = getattr(MalachiWebUI.daemon, 'mesh_node', None) if MalachiWebUI.daemon else None
        if not mesh_node:
            self._send_json({'success': False, 'message': 'Daemon not running.'})
            return

        service_type = data.get('type', 'custom')
        port = data.get('port', 0)

        if not port or not validate_port(port):
            self._send_json({'success': False, 'message': 'Valid port required.'})
            return

        try:
            mesh_node.register_service(service_type, int(port))
            self._send_json({'success': True, 'message': f'Service registered: {service_type} on port {port}'})
        except Exception as e:
            self._send_json({'success': False, 'message': f'Error: {e}'})


# =============================================================================
# Entry Point
# =============================================================================

def run_webui(host: str = "0.0.0.0", port: int = WEBUI_PORT):
    server = HTTPServer((host, port), MalachiWebUI)
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                     MALACHI WEB UI                        ║
    ╠═══════════════════════════════════════════════════════════╣
    ║                                                           ║
    ║   Open in browser:  http://localhost:{port:<5}               ║
    ║                                                           ║
    ║   Modern dashboard with real-time monitoring              ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝

    Press Ctrl+C to stop...
    """)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


def main():
    import argparse
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="Malachi Web UI")
    parser.add_argument("-p", "--port", type=int, default=WEBUI_PORT, help=f"Port (default: {WEBUI_PORT})")
    parser.add_argument("-H", "--host", default="0.0.0.0", help="Host (default: 0.0.0.0)")

    args = parser.parse_args()
    run_webui(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
