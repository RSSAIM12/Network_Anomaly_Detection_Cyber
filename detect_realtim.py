#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import os
import time
import threading
from datetime import datetime

import joblib
from scapy.all import sniff, IP, TCP, UDP
import warnings

warnings.filterwarnings("ignore")  # Ignore les warnings scikit-learn

# -----------------------------
# Configuration
# -----------------------------
MODEL_PATH = "lucid_model.pkl"          # Chemin vers le modèle LUCID
INTERFACE = "enp0s3"                    # Interface réseau à sniffer
API_URL = "http://localhost:5000/api/alert"  # URL de l'API REST
# -----------------------------

# Charger le modèle LUCID
if not os.path.exists(MODEL_PATH):
    print("❌ Modèle introuvable :", MODEL_PATH)
    exit(1)

model = joblib.load(MODEL_PATH)
print(f"✅ Modèle trouvé à : {MODEL_PATH}")

def send_alert(alert):
    """Envoie l'alerte à l'API REST"""
    try:
        response = requests.post(
            API_URL,
            json=alert,
            timeout=2
        )
        if response.status_code == 200:
            print("✅ Alerte envoyée au dashboard")
        else:
            print(f"❌ Erreur envoi alerte: {response.status_code}")
    except Exception as e:
        print(f"❌ Impossible de se connecter au dashboard: {e}")

def process_packet(pkt):
    try:
        proto = -1
        pkt_type = "OTHER"

        size = len(pkt)
        ttl = getattr(pkt, "ttl", -1)

        if TCP in pkt:
            proto = 6
            pkt_type = "TCP"
        elif UDP in pkt:
            proto = 17
            pkt_type = "UDP"
        features = [[size, ttl, proto]]
        pred = model.predict(features)

        if pred[0] == -1:
            alert = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "size": size,
                "ttl": ttl,
                "proto": proto,
                "type": pkt_type
            }
            print(f"⚠️ ATTACK DETECTED → {alert}")
            send_alert(alert)

    except Exception as e:
        print("Erreur process_packet :", e)

def start_sniffer():
    print(f"🚀 Sniffer démarré sur l'interface : {INTERFACE}")
    print("📡 En écoute des paquets réseau...")
    sniff(iface=INTERFACE, prn=process_packet, store=False)

if __name__ == "__main__":
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.start()
