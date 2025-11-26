from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import pickle
import numpy as np
from sklearn.model_selection import train_test_split, cross_validate
from sklearn.multiclass import OneVsRestClassifier
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

# Load features
features = pd.read_csv('NB15_features.csv', engine='python', encoding='latin1')

# Load datasets
df_1 = pd.read_csv('UNSW-NB15_1.csv', encoding='latin1', engine='python')
col_names = features['Name']
df_1.columns = col_names

df_2 = pd.read_csv('UNSW-NB15_2.csv', encoding='latin1', engine='python')
df_2.columns = col_names

df_3 = pd.read_csv('UNSW-NB15_3.csv', encoding='latin1', engine='python')
df_3.columns = col_names

df_4 = pd.read_csv('UNSW-NB15_4.csv', encoding='latin1', engine='python')
df_4.columns = col_names

df = pd.concat([df_1, df_2, df_3, df_4], axis=0)
print(len(df.columns))
print(df.columns)

# Clean attack_cat
df['attack_cat'].fillna('Normal', inplace=True)
df = df[df['attack_cat'] != 'Normal']
df['attack_cat'] = df['attack_cat'].apply(lambda x: x.strip())

# Merge categories
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

# Select features
X = df[['proto', 'Spkts', 'Dpkts', 'tcprtt', 'state', 'dur', 'sbytes',
        'dbytes', 'ct_srv_src', 'ct_srv_dst']]
y = df['attack_cat'].apply(lambda x: x.strip())

# Encode categorical variables
X = pd.get_dummies(X, columns=['proto', 'state'])
y = pd.get_dummies(y)

# Model
clf = RandomForestClassifier(class_weight='balanced', n_estimators=100)
mul_clf = OneVsRestClassifier(clf)

# TRAIN TEST SPLIT (IMPORTANT)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=1)

# Train model
mul_clf.fit(X_train, y_train)

# Predict
preds = mul_clf.predict(X_test)
print("Accuracy:", accuracy_score(preds, y_test))

# Confusion matrix
cm = confusion_matrix(np.array(y_test).argmax(axis=1),
                      np.array(preds).argmax(axis=1))
print(cm)

plt.imshow(cm, interpolation='nearest')
plt.show()

# Save model locally
with open('att_classes.pkl', 'wb') as f:
    pickle.dump(mul_clf, f)

print("Model saved as att_classes.pkl")
