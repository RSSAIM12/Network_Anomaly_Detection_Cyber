import pandas as pd

url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
col_names = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment",
    "urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell",
    "su_attempted","num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label", "difficulty"
]

df = pd.read_csv(url, names=col_names)
df.head()
df = df.drop(columns=["difficulty"])
from sklearn.preprocessing import OneHotEncoder

categorical = ["protocol_type", "service", "flag"]
encoder = OneHotEncoder(sparse_output=False)

encoded_cats = encoder.fit_transform(df[categorical])
encoded_cats = pd.DataFrame(encoded_cats)

df_num = df.drop(columns=categorical + ["label"])
df_full = pd.concat([df_num, encoded_cats], axis=1)

df_full.head()
# Convertir colonnes en string
df_full.columns = df_full.columns.astype(str)

# Séparer normal et attaques correctement
normal_df = df_full[df["label"] == "normal"]
attack_df = df_full[df["label"] != "normal"]

# Scaling
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
X_normal = scaler.fit_transform(normal_df)
X_attack = scaler.transform(attack_df)
import tensorflow as tf
from tensorflow.keras import layers, models

input_dim = X_normal.shape[1]

input_layer = layers.Input(shape=(input_dim,))
encoder = layers.Dense(64, activation='relu')(input_layer)
encoder = layers.Dense(32, activation='relu')(encoder)

latent = layers.Dense(16, activation='relu')(encoder)

decoder = layers.Dense(32, activation='relu')(latent)
decoder = layers.Dense(64, activation='relu')(decoder)
output_layer = layers.Dense(input_dim, activation='linear')(decoder)

autoencoder = models.Model(input_layer, output_layer)
autoencoder.compile(optimizer='adam', loss='mse')

autoencoder.summary()
history = autoencoder.fit(
    X_normal, X_normal,
    epochs=20,
    batch_size=256,
    validation_split=0.1,
    verbose=1
)
recon_errors = np.mean(np.square(X_normal - autoencoder.predict(X_normal)), axis=1)
threshold = np.mean(recon_errors) + 3*np.std(recon_errors)
threshold
# reconstruire toutes les données
X_all = np.concatenate([X_normal, X_attack])
y_all = np.concatenate([np.zeros(len(X_normal)), np.ones(len(X_attack))])

errors = np.mean(np.square(X_all - autoencoder.predict(X_all)), axis=1)
predictions = (errors > threshold).astype(int)
# Reconstruction des erreurs sur normal
recon_errors = np.mean((X_normal - autoencoder.predict(X_normal))**2, axis=1)

# Seuil basé sur percentile 95 au lieu de mean+3*std
threshold = np.percentile(recon_errors, 95)
print("Nouveau seuil d'anomalie :", threshold)

# Tester sur toutes les données
X_all = np.concatenate([X_normal, X_attack])
y_all = np.concatenate([np.zeros(len(X_normal)), np.ones(len(X_attack))])
errors_all = np.mean((X_all - autoencoder.predict(X_all))**2, axis=1)
predictions = (errors_all > threshold).astype(int)

from sklearn.metrics import classification_report, confusion_matrix
print(classification_report(y_all, predictions, target_names=["Normal", "Attack"]))
print(confusion_matrix(y_all, predictions))


# Sauvegarder le scaler
import joblib
joblib.dump(scaler, "lucid.pkl")
