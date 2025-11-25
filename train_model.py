import pickle
import pandas as pd
from sklearn.ensemble import IsolationForest

# ================================
# 1. Charger le dataset
# ================================
df = pd.read_csv("traffic.csv")

# Les features que tu utilises aussi dans detect_realtime.py
FEATURES = ["size", "ttl", "proto"]

# Extraction des features
X = df[FEATURES]

# ================================
# 2. Entraîner le modèle
# ================================
# Modèle léger pour détection d’anomalies / DDoS
model = IsolationForest(
    n_estimators=150,
    contamination=0.05,
    random_state=42
)

print("🔄 Entraînement du modèle en cours...")
model.fit(X)   # ⚠️ IMPORTANT : garder les noms de colonnes pour éviter le warning !

print("✅ Modèle entraîné avec succès.")

# ================================
# 3. Sauvegarde du modèle
# ================================
with open("lucid_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("💾 Modèle sauvegardé → lucid_model.pkl")
