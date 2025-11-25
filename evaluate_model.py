import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# -----------------------------
# 1) Générer données normales
# -----------------------------
normal = pd.DataFrame({
    "size": np.random.randint(60, 1500, 1000),
    "ttl": np.random.choice([64, 128, 255], 1000),
    "proto": np.random.choice([6, 17], 1000),
})
normal["label"] = 0  # 0 = normal

# -----------------------------
# 2) Générer données attaques
# -----------------------------
attack = pd.DataFrame({
    "size": np.random.randint(1, 5000, 400),
    "ttl": np.random.choice([1, 2, 3, 64], 400),
    "proto": np.random.choice([6, 17], 400),
})
attack["label"] = 1  # 1 = attaque

# Dataset complet
df = pd.concat([normal, attack], ignore_index=True)

X = df[["size", "ttl", "proto"]]
y_true = df["label"]  # vrais labels

# -----------------------------
# 3) Entraînement IsolationForest
# -----------------------------
model = IsolationForest(contamination=0.3, random_state=42)
model.fit(X)

# -----------------------------
# 4) Prédictions
# IsolationForest retourne :  1 → normal,  -1 → anomalie
# On convertit :
# -1 devient 1 (attaque), 1 devient 0 (normal)
# -----------------------------
y_pred = model.predict(X)
y_pred = np.where(y_pred == -1, 1, 0)

# -----------------------------
# 5) Calcul métriques
# -----------------------------
accuracy = accuracy_score(y_true, y_pred)
precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)

print("📊 **Évaluation du modèle Isolation Forest**")
print("-------------------------------------------")
print(f"🎯 Accuracy  : {accuracy:.4f}")
print(f"🎯 Precision : {precision:.4f}")
print(f"🎯 Recall    : {recall:.4f}")
print(f"🎯 F1-Score  : {f1:.4f}")
