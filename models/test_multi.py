import pandas as pd
import pickle

# -------------------------
# 1. Charger le dataset test
# -------------------------
df = pd.read_csv('pcaps/UNSW_NB15_testing-set.csv')

# -------------------------
# 2. Prétraitement identique à l'entraînement
# -------------------------
df['attack_cat'].fillna('Normal', inplace=True)
df = df[df['attack_cat'] != 'Normal']
df['attack_cat'] = df['attack_cat'].str.strip()

df['attack_cat'].replace({
    'Exploits': 'DoS',
    'Fuzzers': 'DoS',
    'Reconnaissance': 'Port Scan',
    'Analysis': 'Port Scan',
    'Backdoors': 'Privilege Escalation',
    'Backdoor': 'Privilege Escalation',
    'Shellcode': 'Privilege Escalation',
    'Worms': 'Privilege Escalation'
}, inplace=True)

# -------------------------
# 3. Même features EXACTES qu'à l'entraînement
# -------------------------
X = df[['proto', 'spkts', 'dpkts', 'tcprtt', 'state', 'dur',
        'sbytes', 'dbytes', 'ct_srv_src', 'ct_srv_dst']]   # <= corrigé

# One-hot encoding
X = pd.get_dummies(X, columns=['proto', 'state'])

# -------------------------
# 4. Encoder les labels
# -------------------------
y = pd.get_dummies(df['attack_cat'])

# -------------------------
# 5. Charger ton modèle
# -------------------------
with open("att_classes.pkl", "rb") as f:
    model = pickle.load(f)

# -------------------------
# 6. Réaligner les colonnes
# -------------------------
train_features = model.feature_names_in_

for col in train_features:
    if col not in X.columns:
        X[col] = 0

X = X[train_features]

# -------------------------
# 7. Prédiction
# -------------------------
preds = model.predict(X)

from sklearn.metrics import accuracy_score
print("Accuracy =", accuracy_score(y, preds))
