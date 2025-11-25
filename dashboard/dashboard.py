#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, send_from_directory, request
from datetime import datetime
import threading
import time
import json
import os

# -----------------------------
# Configuration du Dashboard
# -----------------------------
API_PORT = 5000
DASHBOARD_FILE = "dashboard.html"

app = Flask(__name__)

class AlertDashboard:
    def __init__(self):
        self.alerts_history = []
        self.stats = {
            'total_alerts': 0,
            'tcp_alerts': 0,
            'udp_alerts': 0,
            'other_alerts': 0,
            'last_alert_time': None
        }
    
    def add_alert(self, alert_info):
        """Ajoute une nouvelle alerte et met à jour les statistiques"""
        alert_data = {
            'id': len(self.alerts_history) + 1,
            'timestamp': alert_info.get('time', datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            'size': alert_info.get('size', 0),
            'ttl': alert_info.get('ttl', -1),
            'protocol': alert_info.get('proto', -1),
            'type': alert_info.get('type', 'UNKNOWN'),
            'protocol_name': self.get_protocol_name(alert_info.get('proto', -1))
        }
        
        self.alerts_history.append(alert_data)
        self.update_stats(alert_data)
        
        # Garder seulement les 1000 dernières alertes
        if len(self.alerts_history) > 1000:
            self.alerts_history = self.alerts_history[-1000:]
        
        print(f"🚨 Nouvelle alerte reçue: {alert_data['type']} - Taille: {alert_data['size']} octets")
        return alert_data
    
    def update_stats(self, alert_data):
        """Met à jour les statistiques"""
        self.stats['total_alerts'] += 1
        self.stats['last_alert_time'] = alert_data['timestamp']
        
        if alert_data['type'] == 'TCP':
            self.stats['tcp_alerts'] += 1
        elif alert_data['type'] == 'UDP':
            self.stats['udp_alerts'] += 1
        else:
            self.stats['other_alerts'] += 1
    
    def get_protocol_name(self, proto_num):
        """Convertit le numéro de protocol en nom"""
        protocols = {
            6: 'TCP',
            17: 'UDP',
            1: 'ICMP',
            2: 'IGMP'
        }
        return protocols.get(proto_num, f'Proto_{proto_num}')
    
    def get_recent_alerts(self, limit=20):
        """Retourne les alertes récentes"""
        return self.alerts_history[-limit:][::-1]  # Inverser pour avoir les plus récentes en premier

# Instance globale du dashboard
dashboard = AlertDashboard()

# Routes API
@app.route('/')
def serve_dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(dashboard.stats)

@app.route('/api/alerts')
def get_alerts():
    limit = int(request.args.get('limit', 20))
    return jsonify(dashboard.get_recent_alerts(limit))

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    """Reçoit les alertes du sniffer"""
    try:
        alert_data = request.json
        dashboard.add_alert(alert_data)
        return jsonify({'status': 'success', 'message': 'Alerte reçue'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts/count')
def get_alerts_count():
    return jsonify({'count': len(dashboard.alerts_history)})

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

def create_dashboard_html():
    """Crée le fichier HTML du dashboard avec AJAX"""
    html_content = '''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LUCID IDS - Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0c0c0c 0%, #1a1a2e 50%, #16213e 100%);
            color: #ffffff;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            padding: 20px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #ff6b6b, #feca57, #48dbfb, #ff9ff3);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
            animation: pulse 2s infinite;
        }

        .status-active {
            background: #00b894;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }

        .stat-card.alert {
            background: linear-gradient(135deg, #ff6b6b20, #ff6b6b10);
            border: 1px solid #ff6b6b40;
        }

        .stat-card.warning {
            background: linear-gradient(135deg, #feca5720, #feca5710);
            border: 1px solid #feca5740;
        }

        .stat-card.info {
            background: linear-gradient(135deg, #48dbfb20, #48dbfb10);
            border: 1px solid #48dbfb40;
        }

        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }

        .stat-card.alert .stat-number {
            color: #ff6b6b;
        }

        .stat-card.warning .stat-number {
            color: #feca57;
        }

        .stat-card.info .stat-number {
            color: #48dbfb;
        }

        .charts-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 25px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            height: 300px;
        }

        .alerts-container {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .alerts-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .alerts-list {
            max-height: 400px;
            overflow-y: auto;
        }

        .alert-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid #ff6b6b;
            transition: all 0.3s ease;
        }

        .alert-item:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateX(5px);
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .alert-type {
            background: #ff6b6b;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .alert-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 10px;
            font-size: 0.9em;
            color: #cccccc;
        }

        .protocol-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
            font-weight: bold;
        }

        .protocol-tcp {
            background: #48dbfb20;
            color: #48dbfb;
            border: 1px solid #48dbfb40;
        }

        .protocol-udp {
            background: #feca5720;
            color: #feca57;
            border: 1px solid #feca5740;
        }

        .protocol-other {
            background: #ff9ff320;
            color: #ff9ff3;
            border: 1px solid #ff9ff340;
        }

        .controls {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            background: #48dbfb;
            color: white;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s ease;
        }

        .btn:hover {
            background: #369db9;
        }

        .btn-refresh {
            background: #feca57;
        }

        .btn-refresh:hover {
            background: #d4a93d;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .new-alert {
            animation: slideIn 0.5s ease;
        }

        /* Responsive */
        @media (max-width: 768px) {
            .charts-container {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .chart-card {
                height: 250px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> LUCID IDS DASHBOARD</h1>
            <p>Système de Détection d'Intrusions en Temps Réel</p>
            <div class="connection-status">
                <span class="status-indicator status-active"></span>
                <span id="status-text">Connecté</span>
                <span id="last-update" style="margin-left: 20px; color: #ccc;"></span>
            </div>
        </div>

        <div class="controls">
            <button class="btn btn-refresh" onclick="refreshData()">
                <i class="fas fa-sync-alt"></i> Actualiser
            </button>
            <button class="btn" onclick="toggleAutoRefresh()">
                <i class="fas fa-clock"></i> <span id="auto-refresh-text">Auto: ON</span>
            </button>
        </div>

        <div class="stats-grid">
            <div class="stat-card alert">
                <i class="fas fa-exclamation-triangle fa-2x"></i>
                <div class="stat-number" id="total-alerts">0</div>
                <div class="stat-label">Alertes Total</div>
            </div>
            <div class="stat-card warning">
                <i class="fas fa-network-wired fa-2x"></i>
                <div class="stat-number" id="tcp-alerts">0</div>
                <div class="stat-label">Alertes TCP</div>
            </div>
            <div class="stat-card warning">
                <i class="fas fa-broadcast-tower fa-2x"></i>
                <div class="stat-number" id="udp-alerts">0</div>
                <div class="stat-label">Alertes UDP</div>
            </div>
            <div class="stat-card info">
                <i class="fas fa-clock fa-2x"></i>
                <div class="stat-number" id="other-alerts">0</div>
                <div class="stat-label">Autres Alertes</div>
            </div>
        </div>

        <div class="charts-container">
            <div class="chart-card">
                <h3><i class="fas fa-chart-pie"></i> Répartition des Protocoles</h3>
                <canvas id="protocolChart"></canvas>
            </div>
            <div class="chart-card">
                <h3><i class="fas fa-chart-line"></i> Alertes par Minute</h3>
                <canvas id="timelineChart"></canvas>
            </div>
        </div>

        <div class="alerts-container">
            <div class="alerts-header">
                <h3><i class="fas fa-list"></i> Alertes Récentes</h3>
                <span class="last-update" id="last-alert-time">Aucune alerte</span>
            </div>
            <div class="alerts-list" id="alerts-list">
                <div class="no-alerts" id="no-alerts">
                    <p style="text-align: center; color: #666; padding: 40px;">
                        <i class="fas fa-check-circle fa-3x" style="margin-bottom: 20px;"></i><br>
                        Aucune alerte détectée pour le moment
                    </p>
                </div>
            </div>
        </div>
    </div>

    <script>
        class IDSDashboard {
            constructor() {
                this.protocolChart = null;
                this.timelineChart = null;
                this.alertsData = {
                    protocols: { TCP: 0, UDP: 0, OTHER: 0 },
                    timeline: []
                };
                this.autoRefresh = true;
                this.lastAlertCount = 0;
                this.init();
            }

            init() {
                this.initCharts();
                this.loadInitialData();
                this.startAutoRefresh();
            }

            async loadInitialData() {
                await this.loadStats();
                await this.loadAlerts();
            }

            async loadStats() {
                try {
                    const response = await fetch('/api/stats');
                    const stats = await response.json();
                    this.updateStats(stats);
                } catch (error) {
                    console.error('❌ Erreur chargement stats:', error);
                    this.updateStatus('Erreur de connexion', false);
                }
            }

            async loadAlerts() {
                try {
                    const response = await fetch('/api/alerts?limit=50');
                    const alerts = await response.json();
                    this.updateAlertsList(alerts);
                    
                    // Vérifier les nouvelles alertes
                    if (alerts.length > 0 && alerts.length !== this.lastAlertCount) {
                        if (this.lastAlertCount > 0) {
                            this.highlightNewAlerts();
                        }
                        this.lastAlertCount = alerts.length;
                    }
                    
                    this.updateStatus('Connecté', true);
                    this.updateLastUpdateTime();
                } catch (error) {
                    console.error('❌ Erreur chargement alertes:', error);
                    this.updateStatus('Erreur de connexion', false);
                }
            }

            updateStats(stats) {
                document.getElementById('total-alerts').textContent = stats.total_alerts;
                document.getElementById('tcp-alerts').textContent = stats.tcp_alerts;
                document.getElementById('udp-alerts').textContent = stats.udp_alerts;
                document.getElementById('other-alerts').textContent = stats.other_alerts;
                
                if (stats.last_alert_time) {
                    document.getElementById('last-alert-time').textContent = 
                        'Dernière alerte: ' + stats.last_alert_time;
                }
            }

            updateAlertsList(alerts) {
                const alertsList = document.getElementById('alerts-list');
                const noAlerts = document.getElementById('no-alerts');
                
                if (alerts.length === 0) {
                    if (noAlerts) noAlerts.style.display = 'block';
                    return;
                }
                
                if (noAlerts) noAlerts.style.display = 'none';

                alertsList.innerHTML = '';

                alerts.forEach(alert => {
                    this.addAlertToList(alert, false);
                });

                this.updateChartsFromAlerts(alerts);
            }

            addAlertToList(alert, animate = true) {
                const alertsList = document.getElementById('alerts-list');
                const noAlerts = document.getElementById('no-alerts');
                
                if (noAlerts) {
                    noAlerts.style.display = 'none';
                }

                const alertElement = document.createElement('div');
                alertElement.className = `alert-item ${animate ? 'new-alert' : ''}`;
                
                const protocolClass = this.getProtocolClass(alert.protocol_name);
                
                alertElement.innerHTML = `
                    <div class="alert-header">
                        <strong>Alerte #${alert.id}</strong>
                        <span class="alert-type">${alert.type}</span>
                    </div>
                    <div class="alert-details">
                        <div><i class="far fa-clock"></i> ${alert.timestamp}</div>
                        <div><i class="fas fa-weight-hanging"></i> ${alert.size} octets</div>
                        <div><i class="fas fa-hopstarter"></i> TTL: ${alert.ttl}</div>
                        <div><span class="protocol-badge ${protocolClass}">${alert.protocol_name}</span></div>
                    </div>
                `;

                if (animate) {
                    alertsList.insertBefore(alertElement, alertsList.firstChild);
                } else {
                    alertsList.appendChild(alertElement);
                }
            }

            highlightNewAlerts() {
                const newAlerts = document.querySelectorAll('.alert-item');
                if (newAlerts.length > 0) {
                    newAlerts[0].classList.add('new-alert');
                }
            }

            getProtocolClass(protocolName) {
                switch (protocolName.toUpperCase()) {
                    case 'TCP': return 'protocol-tcp';
                    case 'UDP': return 'protocol-udp';
                    default: return 'protocol-other';
                }
            }

            initCharts() {
                // Graphique des protocoles
                const protocolCtx = document.getElementById('protocolChart').getContext('2d');
                this.protocolChart = new Chart(protocolCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['TCP', 'UDP', 'Autres'],
                        datasets: [{
                            data: [0, 0, 0],
                            backgroundColor: [
                                '#48dbfb',
                                '#feca57',
                                '#ff9ff3'
                            ],
                            borderWidth: 2,
                            borderColor: '#1a1a2e'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    color: '#ffffff',
                                    font: {
                                        size: 12
                                    }
                                }
                            }
                        }
                    }
                });

                // Graphique timeline
                const timelineCtx = document.getElementById('timelineChart').getContext('2d');
                this.timelineChart = new Chart(timelineCtx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Alertes par minute',
                            data: [],
                            borderColor: '#ff6b6b',
                            backgroundColor: 'rgba(255, 107, 107, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            x: {
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#ffffff'
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#ffffff'
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#ffffff'
                                }
                            }
                        }
                    }
                });
            }

            updateChartsFromAlerts(alerts) {
                this.alertsData = {
                    protocols: { TCP: 0, UDP: 0, OTHER: 0 },
                    timeline: []
                };

                alerts.forEach(alert => {
                    const protocol = alert.protocol_name.toUpperCase();
                    if (protocol === 'TCP') this.alertsData.protocols.TCP++;
                    else if (protocol === 'UDP') this.alertsData.protocols.UDP++;
                    else this.alertsData.protocols.OTHER++;
                });

                this.protocolChart.data.datasets[0].data = [
                    this.alertsData.protocols.TCP,
                    this.alertsData.protocols.UDP,
                    this.alertsData.protocols.OTHER
                ];
                this.protocolChart.update();

                const timelineData = this.groupAlertsByMinute(alerts);
                this.timelineChart.data.labels = timelineData.labels;
                this.timelineChart.data.datasets[0].data = timelineData.data;
                this.timelineChart.update();
            }

            groupAlertsByMinute(alerts) {
                const groups = {};
                alerts.forEach(alert => {
                    const minute = alert.timestamp.substring(0, 16);
                    groups[minute] = (groups[minute] || 0) + 1;
                });

                const labels = Object.keys(groups).slice(-15);
                const data = labels.map(label => groups[label]);

                return { labels, data };
            }

            updateStatus(message, isConnected) {
                const statusElement = document.getElementById('status-text');
                const indicator = document.querySelector('.status-indicator');
                
                statusElement.textContent = message;
                
                if (isConnected) {
                    indicator.className = 'status-indicator status-active';
                    indicator.style.background = '#00b894';
                } else {
                    indicator.className = 'status-indicator';
                    indicator.style.background = '#ff6b6b';
                }
            }

            updateLastUpdateTime() {
                const now = new Date();
                document.getElementById('last-update').textContent = 
                    'Dernière mise à jour: ' + now.toLocaleTimeString();
            }

            startAutoRefresh() {
                setInterval(() => {
                    if (this.autoRefresh) {
                        this.loadStats();
                        this.loadAlerts();
                    }
                }, 2000);
            }

            toggleAutoRefresh() {
                this.autoRefresh = !this.autoRefresh;
                document.getElementById('auto-refresh-text').textContent = 
                    this.autoRefresh ? 'Auto: ON' : 'Auto: OFF';
            }
        }

        function refreshData() {
            if (window.dashboard) {
                window.dashboard.loadStats();
                window.dashboard.loadAlerts();
            }
        }

        function toggleAutoRefresh() {
            if (window.dashboard) {
                window.dashboard.toggleAutoRefresh();
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            window.dashboard = new IDSDashboard();
        });
    </script>
</body>
</html>
    '''
    
    with open(DASHBOARD_FILE, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"📁 Dashboard HTML créé: {DASHBOARD_FILE}")

def start_dashboard():
    """Démarre le dashboard complet"""
    print("🚀 Démarrage du Dashboard LUCID IDS avec Flask...")
    
    # Créer le fichier HTML du dashboard
    create_dashboard_html()
    
    # Démarrer le serveur Flask
    print(f"🌐 Dashboard démarré sur http://localhost:{API_PORT}")
    app.run(host='0.0.0.0', port=API_PORT, debug=False, threaded=True)

if __name__ == "__main__":
    start_dashboard()
