import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

print("\n=== TRAINING BINARY MODEL ===")

# -----------------------------
# 1. Charger dataset
# -----------------------------
df = pd.read_csv("UNSW_NB15_training-set.csv")

# -----------------------------
# 2. Extraction de X et y
# -----------------------------
y = df["label"]  # 0 = normal, 1 = attaque

X = df[['proto', 'spkts', 'dpkts', 'tcprtt', 'state', 'dur',
        'sbytes', 'dbytes', 'ct_srv_src', 'ct_srv_dst']]

X = pd.get_dummies(X, columns=['proto', 'state'])

# -----------------------------
# 3. Train/Test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# 4. Entraînement RandomForest
# -----------------------------
clf = RandomForestClassifier(
    n_estimators=200,
    class_weight="balanced",
    random_state=42
)

clf.fit(X_train, y_train)

# -----------------------------
# 5. Évaluation
# -----------------------------
preds = clf.predict(X_test)

print("Accuracy:", accuracy_score(y_test, preds))
print("Precision:", precision_score(y_test, preds))
print("Recall:", recall_score(y_test, preds))
print("F1 Score:", f1_score(y_test, preds))

# -----------------------------
# 6. Sauvegarde
# -----------------------------
with open("binary_model.pkl", "wb") as f:
    pickle.dump(clf, f)

print("\nModel saved as binary_model.pkl")
