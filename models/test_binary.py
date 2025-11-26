# %%
import pandas as pd
import pickle
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# -------------------------
# 1. Charger dataset test
# -------------------------
df = pd.read_csv("pcaps/UNSW_NB15_testing-set.csv")

# -------------------------
# 2. Séparer X et y
# -------------------------
y = df["label"]     # 0 = normal, 1 = attaque

# Colonnes utilisées pour le modèle binaire
features = ['proto', 'spkts', 'dpkts', 'tcprtt', 'state', 'dur',
            'sbytes', 'dbytes', 'ct_srv_src', 'ct_srv_dst']

X = df[features]

# -------------------------
# 3. One-hot encoding
# -------------------------
X = pd.get_dummies(X, columns=['proto', 'state'])

# -------------------------
# 4. Charger modèle binaire
# -------------------------
with open("binary_model.pkl", "rb") as f:
    clf = pickle.load(f)

# -------------------------
# 5. Réaligner colonnes avec celles du modèle
# -------------------------
model_features = clf.feature_names_in_

# Ajouter colonnes manquantes
for col in model_features:
    if col not in X.columns:
        X[col] = 0   # ajouter colonne manquante

# Réordonner dans le bon ordre
X = X[model_features]

# -------------------------
# 6. Prédictions
# -------------------------
preds = clf.predict(X)

# -------------------------
# 7. Scores
# -------------------------
print("\n=== EVALUATION BINARY MODEL ===")
print("Accuracy  :", accuracy_score(y, preds))
print("Precision :", precision_score(y, preds))
print("Recall    :", recall_score(y, preds))
print("F1-Score  :", f1_score(y, preds))
